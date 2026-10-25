
import os, re, io, json, csv, time, hmac, hashlib, base64, sqlite3, random, secrets
import streamlit as st
from datetime import datetime

# TIP: to keep data after the Colab runtime resets, mount Google Drive and use e.g.
# DB_PATH = "/content/drive/MyDrive/qbank.db"
DB_PATH    = "qbank_v3.db"
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
SECRET = secrets.token_bytes(32)          # signing key for login tokens (JWT-style)

VALID_TYPES = ("Very Short", "Short", "Long")
TYPE_MARKS  = {"Very Short": 1, "Short": 2, "Long": 10}      # fixed marks per question format

def norm_type(t):
    k = re.sub(r"[^a-z]", "", str(t or "").lower())
    return {"veryshort": "Very Short", "vs": "Very Short", "mcq": "Very Short", "short": "Short", "s": "Short",
            "long": "Long", "l": "Long"}.get(k, "")

# ---------- REVISED Bloom's Taxonomy (Anderson & Krathwohl, 2001) ----------
BLOOM = [
 dict(name="Remembering",   color="#6366f1", icon="🧩", definition="Exhibit memory of previously learned material by recalling facts, terms, basic concepts, and answers.",
      verbs="Choose,Define,Find,How,Label,List,Match,Name,Omit,Recall,Relate,Select,Show,Spell,Tell,What,When,Where,Which,Who,Why"),
 dict(name="Understanding", color="#0ea5e9", icon="💡", definition="Demonstrate understanding of facts and ideas by organizing, comparing, translating, interpreting, giving descriptions, and stating main ideas.",
      verbs="Classify,Compare,Contrast,Demonstrate,Explain,Extend,Illustrate,Infer,Interpret,Outline,Relate,Rephrase,Show,Summarize,Translate"),
 dict(name="Applying",      color="#10b981", icon="🛠️", definition="Solve problems to new situations by applying acquired knowledge, facts, techniques and rules in a different way.",
      verbs="Apply,Build,Choose,Construct,Develop,Experiment with,Identify,Interview,Make use of,Model,Organize,Plan,Select,Solve,Utilize"),
 dict(name="Analyzing",     color="#f59e0b", icon="🔍", definition="Examine and break information into parts by identifying motives or causes. Make inferences and find evidence to support generalizations.",
      verbs="Analyze,Assume,Categorize,Classify,Compare,Conclusion,Contrast,Discover,Dissect,Distinguish,Divide,Examine,Function,Inference,Inspect,List,Motive,Relationships,Simplify,Survey,Take part in,Test for,Theme"),
 dict(name="Evaluating",    color="#f97316", icon="⚖️", definition="Present and defend opinions by making judgments about information, validity of ideas, or quality of work based on a set of criteria.",
      verbs="Agree,Appraise,Assess,Award,Choose,Compare,Conclude,Criteria,Criticize,Decide,Deduct,Defend,Determine,Disprove,Estimate,Evaluate,Explain,Importance,Influence,Interpret,Judge,Justify,Mark,Measure,Opinion,Perceive,Prioritize,Prove,Rate,Recommend,Rule on,Select,Support,Value"),
 dict(name="Creating",      color="#ec4899", icon="🎨", definition="Compile information together in a different way by combining elements in a new pattern or proposing alternative solutions.",
      verbs="Adapt,Build,Change,Choose,Combine,Compile,Compose,Construct,Create,Delete,Design,Develop,Discuss,Elaborate,Estimate,Formulate,Happen,Imagine,Improve,Invent,Make up,Maximize,Minimize,Modify,Original,Originate,Plan,Predict,Propose,Solution,Solve,Suppose,Test,Theory"),
]
for _b in BLOOM: _b["verbs"] = _b["verbs"].split(",")
LEVELS = tuple(b["name"] for b in BLOOM)
LEVEL_ORDER = {n: i for i, n in enumerate(LEVELS)}

def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('Faculty','Student')));
        CREATE TABLE IF NOT EXISTS subject_units(subject TEXT, unit TEXT, title TEXT, PRIMARY KEY(subject, unit));
        CREATE TABLE IF NOT EXISTS questionbank(
            id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, subject TEXT,
            description TEXT, file TEXT, faculty_id INTEGER, upload_date TEXT);
        CREATE TABLE IF NOT EXISTS questions(
            id INTEGER PRIMARY KEY AUTOINCREMENT, question TEXT NOT NULL,
            answer TEXT, options TEXT, subject TEXT, unit TEXT, topic TEXT,
            bloom_level TEXT, verb TEXT, question_type TEXT, marks INTEGER,
            faculty_id INTEGER, bank_id INTEGER, qstyle TEXT DEFAULT 'Theory');
        """)
        try: c.execute("ALTER TABLE questions ADD COLUMN qstyle TEXT DEFAULT 'Theory'")   # upgrade an older database
        except sqlite3.OperationalError: pass                                              # column already there
def _add_parts_col():
    with db() as c:
        try: c.execute("ALTER TABLE questions ADD COLUMN parts TEXT")   # stem + parts a),b),c)... of Long questions
        except sqlite3.OperationalError: pass
init_db(); _add_parts_col()

# ---------- password hashing (PBKDF2) ----------
def hash_pw(pw, salt=None):
    salt = salt or os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 120_000)
    return salt.hex() + "$" + h.hex()

def check_pw(pw, stored):
    salt, h = stored.split("$")
    return hmac.compare_digest(hash_pw(pw, bytes.fromhex(salt)).split("$")[1], h)

# ---------- JWT-style signed tokens (HMAC-SHA256) ----------
def _b64(b):  return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def _ub64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def make_token(payload, ttl=3600):
    body = _b64(json.dumps({**payload, "exp": time.time() + ttl}).encode())
    sig  = _b64(hmac.new(SECRET, body.encode(), hashlib.sha256).digest())
    return body + "." + sig

def verify_token(tok):
    try:
        body, sig = tok.split(".")
        good = _b64(hmac.new(SECRET, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, good): return None
        p = json.loads(_ub64(body))
        return p if p["exp"] > time.time() else None
    except Exception:
        return None

def require_role(token, role):
    p = verify_token(token) if token else None
    if not p:               raise PermissionError("Session expired. Please log in again.")
    if p["role"] != role:   raise PermissionError(f"Only {role} users can do this.")
    return p

# ---------- FR1 registration / FR2 login ----------
def register(name, email, password, role):
    name, email = name.strip(), email.strip().lower()
    if not name:                                          raise ValueError("Name is required.")
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email): raise ValueError("Enter a valid email.")
    if len(password) < 6:                                 raise ValueError("Password must be at least 6 characters.")
    if role != "Faculty":                                 raise ValueError("Only faculty accounts are available.")
    try:
        with db() as c:
            c.execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)",
                      (name, email, hash_pw(password), role))
    except sqlite3.IntegrityError:
        raise ValueError("This email is already registered.")

def login(email, password):
    with db() as c:
        u = c.execute("SELECT * FROM users WHERE email=?", (email.strip().lower(),)).fetchone()
    if not u or not check_pw(password, u["password"]):
        raise ValueError("Invalid email or password.")
    if u["role"] != "Faculty":
        raise ValueError("Student login has been removed. Please use a faculty account.")
    return make_token({"uid": u["id"], "name": u["name"], "role": u["role"]}), dict(u)
print("✅ Database and authentication ready")
# ============ CELL 3: READ FILES, PARSE SYLLABUS, GENERATE QUESTIONS (offline NLP + AI engine) ============
import numpy as np
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer, ENGLISH_STOP_WORDS

# ---------- reading uploaded files ----------
def read_file(name, data):
    ext = name.lower().rsplit(".", 1)[-1]
    if ext == "pdf":
        from pypdf import PdfReader
        text = "\n".join((p.extract_text() or "") for p in PdfReader(io.BytesIO(data)).pages)
    elif ext == "docx":
        import docx
        text = "\n".join(p.text for p in docx.Document(io.BytesIO(data)).paragraphs)
    else:
        text = data.decode("utf-8", errors="ignore")
    text = re.sub(r"-\n(\w)", r"\1", text)                       # join hyphenated line breaks
    text = "\n".join(l for l in text.splitlines() if not re.fullmatch(r"\s*(page\s*)?\d+\s*", l, re.I))
    return text

# ---------- syllabus parsing ----------
ROMAN = {"i":1,"ii":2,"iii":3,"iv":4,"v":5,"vi":6,"vii":7,"viii":8,"ix":9,"x":10}
UNIT_RE = re.compile(r"^\s*(?:unit|module|chapter)\s*[-:.]?\s*([ivx]+|\d+)\b\s*[:\-–.]?\s*(.*)$", re.I)

# "9 Hrs", "(10 Hours)", "12 periods", "3 credits" are teaching-time labels, NOT topics
HOURS_RE = re.compile(r"\(?\s*\b\d+(?:\.\d+)?\s*(?:hrs?|hours?|periods?|lectures?|lecture\s*hours?|credits?|marks?)\b\.?\s*\)?", re.I)
# headings after which the lines are NOT syllabus topics (book lists, outcomes, totals ...)
STOP_HEAD = re.compile(r"^\s*(?:text\s*books?|reference\s*books?|references?|suggested\s*readings?|course\s*outcomes?|"
                       r"course\s*objectives?|e-?\s*resources?|web\s*resources?|total\s*[:\-]?\s*\d+)", re.I)

def _clean_line(s):
    s = HOURS_RE.sub(" ", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip(" .-–:;,|()[]")

def _valid_topic(t):
    if len(re.findall(r"[A-Za-z]", t)) < 3: return False                       # numbers / "9", "Hrs"
    if re.fullmatch(r"(?:co|unit|module|chapter)\s*\d+", t, re.I): return False
    return True

def _split_topics(s):
    s = _clean_line(s)
    parts = re.split(r"[;,•|]|\s[-–]\s", s)
    parts = [p.strip(" .-•*\t") for p in parts]
    return [p for p in parts if _valid_topic(p)]

def parse_syllabus(text):
    units, cur = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line: continue
        m = UNIT_RE.match(line)
        if m:
            n = m.group(1).lower()
            cur = f"Unit {ROMAN.get(n, n)}"
            units.setdefault(cur, {"title": "", "topics": []})
            rest = _clean_line(m.group(2))                 # "Unit 1 – 9 Hrs"  ->  "" (no fake topic)
            if rest:
                if not units[cur]["title"]: units[cur]["title"] = rest.split(":")[0][:80]
                units[cur]["topics"] += _split_topics(rest)
        elif STOP_HEAD.match(line):
            cur = None                                     # text books / references / outcomes: ignore
        elif cur:
            units[cur]["topics"] += _split_topics(line)
    if not units:   # fallback: no "Unit X" headings found
        units = {"Unit 1": {"title": "General", "topics": _split_topics(text.replace("\n", ",")) or ["General"]}}
    for u in units.values():
        u["topics"] = list(dict.fromkeys(u["topics"]))
        if not u["title"]: u["title"] = u["topics"][0] if u["topics"] else "General"
        if not u["topics"]: u["topics"] = [u["title"]]
    return units

# ---------- textbook -> unit/topic chunks ----------
def split_sentences(text):
    text = re.sub(r"\s+", " ", text)
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])", text)
    return [p.strip() for p in parts if 40 <= len(p.strip()) <= 400]

def build_unit_chunks(units, book_text, window=3, min_sim=0.04):
    sents = split_sentences(book_text)
    chunks = [sents[i:i+window] for i in range(0, len(sents), window)]
    if not chunks: return {}
    texts = [" ".join(c) for c in chunks]
    names = list(units)
    udocs = [units[n]["title"] + " " + " ".join(units[n]["topics"]) for n in names]
    vec = TfidfVectorizer(stop_words="english", sublinear_tf=True).fit(texts + udocs)
    C, U = vec.transform(texts), vec.transform(udocs)
    sim = (C @ U.T).toarray()
    topic_mats = {n: vec.transform(units[n]["topics"]) for n in names}
    result = {n: [] for n in names}
    for i, ch in enumerate(chunks):
        j = int(sim[i].argmax())
        if sim[i, j] < min_sim: continue
        n = names[j]
        ts = (topic_mats[n] @ C[i].T).toarray().ravel()
        topic = units[n]["topics"][int(ts.argmax())] if ts.max() > 0 else units[n]["title"]
        result[n].append((topic, ch))
    return {n: v for n, v in result.items() if v}

# ---------- key-term extraction (TF-IDF, filtered by syllabus relevance) ----------
GENERIC = set("""define called change level represents represent include includes including involves involve
requires require improve improves reduce reduces used using use based make makes help helps provide provides
allow allows enable enables defined type types kind kinds follows following example examples number way ways
part parts form forms thing things given also well often usually generally typically different various several
certain similar common general specific important main basic simple stronger every each other another""".split())

def _stem(w):
    w = w.lower()
    if w.endswith("ies") and len(w) > 4: return w[:-3] + "y"
    if w.endswith("s") and not w.endswith("ss") and len(w) > 3: return w[:-1]
    return w

def syllabus_vocab(unit):
    words = re.findall(r"[A-Za-z]{3,}", unit["title"] + " " + " ".join(unit["topics"]))
    return {_stem(w) for w in words}

def key_terms(docs, vocab=frozenset(), k=20):
    if not docs: return []
    vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True,
                          token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z\-]*\b")
    try: X = vec.fit_transform(docs)
    except ValueError: return []
    scores = np.asarray(X.sum(axis=0)).ravel()
    df = np.asarray((X > 0).sum(axis=0)).ravel()
    terms = vec.get_feature_names_out()
    out = []
    for i in scores.argsort()[::-1]:
        t = terms[i]; words = t.split()
        if any(len(w) < 3 or w in GENERIC or w in ENGLISH_STOP_WORDS or w.endswith("ed") for w in words): continue
        if not ({_stem(w) for w in words} & vocab) and df[i] < 3: continue
        if len(words) == 1 and any(t in o.split() for o in out if " " in o): continue
        out.append(t)
        if len(out) >= k: break
    bigram_words = {w for o in out if " " in o for w in o.split()}
    return [o for o in out if " " in o or o not in bigram_words]

def pretty(term):
    w = term.split()
    if len(w) > 1 and w[0][0].isupper() and all(x.islower() for x in w[0][1:]) and all(x.islower() for x in w[1:]):
        return term[0].lower() + term[1:]
    return term

# ---------- sentence patterns ----------
STOP_START = {"this","that","these","those","it","they","he","she","there","which","what","when","where",
              "who","here","such","some","many","each","one","we","you","its","their","however","thus"}
STOP_END = {"is","are","of","and","or","to","in","a","the","for","with","by","as"}
DEF_STRONG = re.compile(r"^(?P<term>[A-Z][^,.;:?!]{2,60}?)\s+(?:refers to|is defined as|are defined as|can be defined as|means|is termed)\s+(?P<d>.{20,300}?)\.?$")
DEF_WEAK   = re.compile(r"^(?P<term>[A-Z][^,.;:?!]{2,60}?)\s+(?:is|are)\s+(?P<d>(?:a|an|the|any|one|set of|collection of)\s.{20,300}?)\.?$")
DEF_CALLED = re.compile(r"^(?P<d>.{25,250}?)\s+(?:is|are)\s+(?:called|known as|termed)\s+(?P<term>[^,.;:?!]{3,50})\.?$")
TYPES_RE   = re.compile(r"(?:types|kinds|categories|forms|classes) of ([A-Za-z][\w\- ]{2,40}?)(?:\s+(?:are|is|include|includes|namely)\b|[:,.])", re.I)

def clean_term(t):
    t = re.sub(r"^(?:a|an|the)\s+", "", t.strip(), flags=re.I).strip(" ,:;-")
    w = t.split()
    if not 1 <= len(w) <= 5 or w[0].lower() in STOP_START or w[-1].lower() in STOP_END: return None
    return t

def extract_definition(s):
    m = DEF_STRONG.match(s) or DEF_WEAK.match(s)
    if m:
        t = clean_term(m.group("term"))
        return (t, m.group("d").strip()) if t else None
    m = DEF_CALLED.match(s)
    if m:
        t = clean_term(m.group("term"))
        return (t, m.group("d").strip()) if t else None
    return None

def _norm(q): return re.sub(r"[^a-z0-9 ]", "", q.lower()).strip()

# ---------- Bloom-level templates: (question text, format). Marks are fixed by format: Very Short=1, Short=2, Long=10
TERM_TEMPLATES = {
 "Remembering":   [("What is {t}?", "Very Short"), ("Name the key ideas associated with {t}.", "Very Short"),
                   ("Recall one important fact about {t}.", "Very Short"), ("List any four facts you can recall about {t}.", "Short"),
                   ("State any two characteristics of {t}.", "Short"), ("List and describe all the important facts you can recall about {t}.", "Long")],
 "Understanding": [("Rephrase {t} in one line.", "Very Short"), ("State in one line what {t} means.", "Very Short"),
                   ("Summarize {t} in your own words.", "Short"), ("Illustrate {t} with a suitable example.", "Short"),
                   ("Outline the main ideas of {t}.", "Short"), ("Explain {t} in detail with suitable examples.", "Long")],
 "Applying":      [("Identify one practical use of {t}.", "Very Short"), ("Name one situation where {t} can be applied.", "Very Short"),
                   ("Identify a practical situation where {t} is used and show how it is utilized.", "Short"),
                   ("Construct a simple example that demonstrates {t}.", "Short"),
                   ("Apply the concept of {t} to a real-world scenario of your choice.", "Long"),
                   ("Solve a problem that demonstrates the use of {t}, showing each step.", "Long")],
 "Analyzing":     [("Categorize {t} into its main kinds (just name them).", "Very Short"), ("Name any two components of {t}.", "Very Short"),
                   ("Examine the causes and effects associated with {t}.", "Short"), ("Distinguish the parts that make up {t}.", "Short"),
                   ("Analyze the key components of {t} and how they work together.", "Long"), ("Categorize and examine the main aspects of {t}.", "Long")],
 "Evaluating":    [("Justify the need for {t} in one sentence.", "Very Short"), ("State one limitation of {t}.", "Very Short"),
                   ("Assess the strengths and weaknesses of {t}.", "Short"), ("Judge whether {t} is essential, giving two reasons.", "Short"),
                   ("Evaluate the importance of {t} in {tp}.", "Long"), ("Justify the need for {t} with suitable arguments.", "Long")],
 "Creating":      [("Suppose {t} did not exist; predict one consequence.", "Very Short"), ("Suggest one new use for {t}.", "Very Short"),
                   ("Propose an improvement to the way {t} is commonly used.", "Short"), ("Design a simple example that uses {t}.", "Short"),
                   ("Design a small solution or case study that uses {t}.", "Long"),
                   ("Suppose {t} were not available; predict the consequences and suggest an alternative.", "Long")],
}

def generate_for_unit(unit, chunks, vocab=frozenset()):
    out, seen = [], set()
    all_sents = [(topic, s) for topic, ch in chunks for s in ch]
    terms = key_terms([" ".join(ch) for _, ch in chunks], vocab)

    def evidence(term, n=3):
        return " ".join([s for _, s in all_sents if term.lower() in s.lower()][:n])[:700]

    def topic_of(term):
        for tp, s in all_sents:
            if term.lower() in s.lower(): return tp
        return chunks[0][0]

    def add(q, level, typ, topic, ans=""):
        k = _norm(q)
        if k in seen or len(q) < 12: return
        seen.add(k)
        out.append(dict(question=q, answer=ans, options=[], unit=unit, topic=topic, bloom_level=level,
                        verb=q.split()[0].strip(".,:;?"), question_type=typ, marks=TYPE_MARKS[typ]))

    # ---- definitions
    defs = []
    for tp, s in all_sents:
        d = extract_definition(s)
        if d: defs.append((pretty(d[0]), d[1], tp, s))
    for term, dfn, tp, s in defs:
        add(f"Define {term}.", "Remembering", "Short", tp, s)
        add(f'Name the term described as: "{dfn[:160].rstrip()}"', "Remembering", "Very Short", tp, term)
        add(f"Explain {term} with a suitable example.", "Understanding", "Short", tp, evidence(term) or s)
        add(f"Rephrase the definition of {term} in simple words.", "Understanding", "Short", tp, s)

    # ---- sentence patterns
    for tp, s in all_sents:
        low = s.lower()
        in_s = [t for t in terms if t.lower() in low]
        main = max(in_s, key=len) if in_s else tp
        def subj(word):
            m2 = re.search(word + r"\s+of\s+(?:the\s+)?([A-Za-z][\w\- ]{1,30}?)(?=\s+(?:include|are|is|can|may|in|for)\b|[,.;])", s, re.I)
            return m2.group(1).strip() if m2 else main
        if in_s and 50 <= len(s) <= 220 and not extract_definition(s) and re.search(re.escape(main) + r"(?![A-Za-z])", s, re.I):
            blank = re.sub(re.escape(main), "_____", s, count=1, flags=re.I)
            add("Fill in the blank: " + blank, "Remembering", "Very Short", tp, main)
        if re.search(r"\badvantages?\b|\bbenefits?\b", low):
            add(f"Analyze the advantages of {subj(r'(?:advantages?|benefits?)')}.", "Analyzing", "Short", tp, s)
        if re.search(r"\bdisadvantages?\b|\blimitations?\b|\bdrawbacks?\b", low):
            add(f"Assess the limitations of {subj(r'(?:disadvantages?|limitations?|drawbacks?)')}.", "Evaluating", "Short", tp, s)
        if re.search(r"\b(important|essential|crucial|significant)\b", low):
            add(f"Evaluate the importance of {main}.", "Evaluating", "Long", tp, s)
        m = TYPES_RE.search(s)
        if m:
            add(f"Classify and explain the different types of {m.group(1).strip()}.", "Understanding", "Long", tp, evidence(m.group(1)) or s)
        if re.search(r"\b(steps?|process|procedure|algorithm|phases?|stages?|life ?cycle)\b", low):
            add(f"Construct a flow diagram showing the steps involved in {main}.", "Applying", "Long", tp, s)

    # ---- syllabus-topic questions
    by_topic = {}
    for tp, ch in chunks: by_topic.setdefault(tp, []).extend(ch)
    for tp, ss in by_topic.items():
        if len(tp) > 4 and not re.search(r"\d", tp):
            add(f"Explain {pretty(tp)} in detail.", "Understanding", "Long", tp, " ".join(ss)[:700])

    # ---- key-term questions: every Bloom level and every format
    for t in terms[:12]:
        tp, ev = topic_of(t), evidence(t, 4)
        for level, temps in TERM_TEMPLATES.items():
            for text, typ in temps:
                add(text.format(t=t, tp=tp), level, typ, tp, ev)

    # ---- pair questions
    for tp, ch in chunks:
        txt = " ".join(ch).lower()
        here = list(dict.fromkeys(t for t in terms if t.lower() in txt))
        if len(here) >= 2 and here[0] not in here[1] and here[1] not in here[0]:
            a, b = here[0], here[1]
            ev = evidence(a, 2) + " " + evidence(b, 2)
            add(f"Compare {a} and {b}.", "Understanding", "Short", tp, ev)
            add(f"Distinguish between {a} and {b}.", "Analyzing", "Long", tp, ev)
            add(f"Examine the relationship between {a} and {b}.", "Analyzing", "Long", tp, ev)
            add(f"Formulate a scenario that combines {a} and {b}, and propose a solution for it.", "Creating", "Long", tp, ev)
    return out

def generate_all(units, book_text):
    unit_chunks = build_unit_chunks(units, book_text)
    qs = []
    for unit, chunks in unit_chunks.items():
        qs += generate_for_unit(unit, chunks, syllabus_vocab(units[unit]))
    return qs

def generate_from_syllabus(units):
    """No textbook (or no textbook text for a unit): build questions from the syllabus topics alone."""
    qs, seen = [], set()
    def add(q, level, typ, unit, topic):
        k = (_norm(q), unit)
        if k in seen: return
        seen.add(k)
        qs.append(dict(question=q, answer="", options=[], unit=unit, topic=topic, bloom_level=level,
                       verb=q.split()[0].strip(".,:;?"), question_type=typ, marks=TYPE_MARKS[typ]))
    for unit, u in units.items():
        topics = [t for t in dict.fromkeys(pretty(t) for t in u["topics"]) if len(t) > 3]
        for t in topics:
            for level, temps in TERM_TEMPLATES.items():
                for text, typ in temps:
                    add(text.format(t=t, tp=u["title"]), level, typ, unit, t)
        for a, b in zip(topics, topics[1:]):
            add(f"Compare {a} and {b}.", "Understanding", "Short", unit, a)
            add(f"Distinguish between {a} and {b}.", "Analyzing", "Long", unit, a)
            add(f"Examine the relationship between {a} and {b}.", "Analyzing", "Long", unit, a)
            add(f"Formulate a scenario that combines {a} and {b}, and propose a solution for it.", "Creating", "Long", unit, a)
    return qs

# ---------- limit the number of questions (per unit, per format) ----------
def _balanced_pick(pool, n):
    """Pick up to n questions, rotating through the 6 Bloom levels and preferring topics not used yet."""
    if n <= 0: return []
    by_level = {l: [] for l in LEVELS}
    pool = list(pool); random.shuffle(pool)
    for q in pool: by_level[q["bloom_level"]].append(q)
    used, out = Counter(), []
    while len(out) < n and any(by_level.values()):
        for l in LEVELS:
            lst = by_level[l]
            if not lst: continue
            best = min(lst, key=lambda q: used[q.get("topic", "")])
            lst.remove(best); out.append(best); used[best.get("topic", "")] += 1
            if len(out) >= n: break
    return out

def select_limited(qs, limits, unit_names, level="All Levels"):
    """limits = {"Very Short": 20, "Short": 10, "Long": 5} -> that many questions PER UNIT for each format.
    level: "All Levels"  = the count is shared (rotated) across the six Bloom levels
           "Each Level"  = that many questions for EVERY Bloom level
           "<one level>" = only that Bloom level (e.g. "Analyzing")
    Returns (chosen questions, list of shortfall messages)."""
    chosen, short = [], []
    if level == "Each Level": level_runs = [(l, l) for l in LEVELS]
    elif level in LEVELS:     level_runs = [(level, level)]
    else:                     level_runs = [("All Levels", None)]
    for unit in unit_names:
        for typ in VALID_TYPES:
            want = int(limits.get(typ, 0))
            if want <= 0: continue
            for label, lv in level_runs:
                pool = [q for q in qs if q["unit"] == unit and q["question_type"] == typ and (lv is None or q["bloom_level"] == lv)]
                got = _balanced_pick(pool, want)
                chosen += got
                if len(got) < want:
                    tag = "" if lv is None else f" {lv}"
                    short.append(f"{unit} – {typ}{tag}: asked for {want}, only {len(got)} could be generated")
    return chosen, short


# ---------- question STYLES: Theory (default) / Scenario / Programming ----------
STYLES = ("Theory", "Scenario", "Programming")
def norm_style(s):
    s = (s or "").strip().title()
    return s if s in STYLES else "Theory"

SCENARIO_ORGS = ["A bank", "A hospital", "A university campus", "An online shopping company",
                 "A software startup", "A government office", "A telecom company", "A school"]
LANGS = ["C", "Java", "Python"]

# (Bloom level, format, text)   {t}=topic  {org}=organisation  {lang}=programming language
SCENARIO_TEMPLATES = [
 ("Remembering",   "Very Short", "{org} uses {t} in its daily work. Name one key term associated with {t}."),
 ("Remembering",   "Short",      "{org} is training new staff on {t}. List the key points they must remember."),
 ("Remembering",   "Long",       "{org} is preparing a staff manual on {t}. Write down in detail the important facts, terms and steps the staff must remember."),
 ("Understanding", "Very Short", "{org} asks what {t} means. State it in one line."),
 ("Understanding", "Short",      "{org} wants its new employees to understand {t}. Explain it in simple terms using an example from its daily work."),
 ("Understanding", "Long",       "{org} wants a detailed report on {t}. Explain {t} thoroughly with suitable examples from its daily work."),
 ("Applying",      "Very Short", "{org} has introduced {t}. State one purpose it serves there."),
 ("Applying",      "Short",      "{org} wants to introduce {t} in its work. Describe how it would be applied."),
 ("Applying",      "Long",       "{org} is facing a problem that can be solved using {t}. Apply the concepts of {t} to solve the problem, showing each step clearly."),
 ("Analyzing",     "Very Short", "{org} reports a failure related to {t}. Name one possible cause."),
 ("Analyzing",     "Short",      "{org} has noticed that {t} is not working as expected. Analyze two possible causes."),
 ("Analyzing",     "Long",       "{org} runs a system based on {t}. Analyze the components involved, find the likely bottlenecks and explain how they affect the system."),
 ("Evaluating",    "Very Short", "{org} is considering {t}. State one reason for or against adopting it."),
 ("Evaluating",    "Short",      "{org} must decide whether to adopt {t}. Evaluate its advantages and drawbacks for this situation."),
 ("Evaluating",    "Long",       "{org} has two options to solve its problem, and one of them is based on {t}. Evaluate both options and justify which one you would recommend."),
 ("Creating",      "Very Short", "{org} wants a new feature based on {t}. Suggest one idea."),
 ("Creating",      "Short",      "{org} wants to improve its service using {t}. Propose a simple solution."),
 ("Creating",      "Long",       "{org} wants to improve its service and reduce errors. Design a complete solution using {t}, and explain how it will work."),
]
PROGRAMMING_TEMPLATES = [
 ("Remembering",   "Very Short", "Name the command, keyword or function mostly used in {t}."),
 ("Remembering",   "Short",      "List the main steps of the algorithm used for {t}."),
 ("Remembering",   "Long",       "Write down the complete algorithm for {t} and list its inputs, outputs and the data structures involved."),
 ("Understanding", "Very Short", "State the input and the output of a program that implements {t}."),
 ("Understanding", "Short",      "Explain how {t} works using a short {lang} code snippet or pseudocode."),
 ("Understanding", "Long",       "Explain the algorithm for {t} step by step, and write its {lang} code or pseudocode with an example run."),
 ("Applying",      "Very Short", "Write one statement or command used to implement {t}."),
 ("Applying",      "Short",      "Write a short {lang} program or pseudocode to demonstrate {t}."),
 ("Applying",      "Long",       "Write a complete {lang} program to implement {t}. Include comments, a sample input and the expected output."),
 ("Analyzing",     "Very Short", "Name one common error that occurs while programming {t}."),
 ("Analyzing",     "Short",      "Trace the working of a simple {lang} program that implements {t} for a sample input and show its output."),
 ("Analyzing",     "Long",       "A {lang} program that implements {t} gives wrong output. Analyze the possible bugs, explain how you would debug it and give the corrected logic."),
 ("Evaluating",    "Very Short", "State one reason for choosing a particular algorithm to implement {t}."),
 ("Evaluating",    "Short",      "Compare two ways of implementing {t} in {lang} and state which one is more efficient."),
 ("Evaluating",    "Long",       "Evaluate the time and space complexity of an algorithm that implements {t}, and justify whether it is suitable for large inputs."),
 ("Creating",      "Very Short", "Suggest one test input for a program that implements {t}."),
 ("Creating",      "Short",      "Design a set of test cases (at least three inputs with expected outputs) for a {lang} program on {t}."),
 ("Creating",      "Long",       "Design an algorithm and write a {lang} program for a new application that uses {t}. Explain your design choices and show a sample run."),
]
APPLIED_GUIDE = {
 "Scenario": {
  "Remembering":   "Marking guide: key terms and facts about {t} recalled correctly.",
  "Understanding": "Marking guide: clear explanation of {t}, linked to the situation, with an example.",
  "Applying":      "Marking guide: {t} applied correctly to the situation, steps shown, clear final result.",
  "Analyzing":     "Marking guide: causes / components identified and their effect on the situation explained.",
  "Evaluating":    "Marking guide: strengths and weaknesses weighed, decision justified with reasons.",
  "Creating":      "Marking guide: workable design using {t}, working explained, benefits stated."},
 "Programming": {
  "Remembering":   "Marking guide: correct commands / steps for {t}.",
  "Understanding": "Marking guide: correct explanation of {t} with valid code or pseudocode.",
  "Applying":      "Marking guide: correct logic and syntax for {t}, comments, sample input and output.",
  "Analyzing":     "Marking guide: step-by-step trace or bug analysis, correct output / fix.",
  "Evaluating":    "Marking guide: comparison or complexity reasoning is correct and justified.",
  "Creating":      "Marking guide: valid design, correct code, test cases covering normal and edge inputs."}}

def generate_applied(units, style):
    """Scenario / Programming questions built from the syllabus topics of every unit (3 variations per topic)."""
    templates = SCENARIO_TEMPLATES if style == "Scenario" else PROGRAMMING_TEMPLATES
    qs, seen, k = [], set(), 0
    for unit, u in units.items():
        topics = [t for t in dict.fromkeys(pretty(t) for t in u["topics"]) if len(t) > 3]
        for t in topics:
            for level, typ, text in templates:
                for _ in range(3):
                    org, lang = SCENARIO_ORGS[k % len(SCENARIO_ORGS)], LANGS[k % len(LANGS)]; k += 1
                    q = text.format(t=t, org=org, lang=lang)
                    key = (_norm(q), unit)
                    if key in seen: continue
                    seen.add(key)
                    qs.append(dict(question=q, answer=APPLIED_GUIDE[style][level].format(t=t), options=[], unit=unit, topic=t,
                                   bloom_level=level, verb=q.split()[0].strip(".,:;?"), question_type=typ,
                                   marks=TYPE_MARKS[typ], qstyle=style))
    return qs

# ======================= AI ENGINE (Gemini or Groq) =======================
# Paste a free API key on the Generate page (or save it as a Colab secret named LLM_KEY).
#   Gemini key: https://aistudio.google.com/apikey   (starts with "AIza")
#   Groq key  : https://console.groq.com/keys        (starts with "gsk_")
import requests, math, threading

LLM_CONFIG = {   # budget = max size of ONE AI call (see CALL_WEIGHT), max_out = output tokens allowed, gap = seconds between request starts (free-tier RPM)
    "gemini": dict(models=["gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-flash-latest", "gemini-flash-lite-latest"],
                   ref_chars=7000, workers=4, budget=200, max_out=16384, gap=6.0),
    "groq":   dict(models=["llama-3.3-70b-versatile", "llama-3.1-8b-instant"],
                   ref_chars=3500, workers=2, budget=70, max_out=8000, gap=2.5),
}

# ---- API key configuration (server-side only) ----------------------------------
# Set LLM_KEY in your hosting platform's environment/secrets settings.
# Never paste a real API key into this source file or commit it to GitHub.

def _load_default_key():
    """Load the AI provider key from a server-side environment variable."""
    return os.environ.get("LLM_KEY", "").strip()

DEFAULT_KEY = _load_default_key()

def get_llm_key(form_key=""):
    return (form_key or "").strip() or DEFAULT_KEY

def detect_provider(key):
    return "groq" if key.startswith("gsk_") else "gemini"

class LLMError(Exception):
    def __init__(self, msg, fatal=False):
        super().__init__(msg); self.fatal = fatal

_MODEL_OK = {}     # provider -> model name that worked last time
_MODEL_BAD = set() # models whose DAILY quota is used up - skipped from then on
_RL = {"lock": threading.Lock(), "next": 0.0}

def _pace(prov):
    """Space the request starts out so the free-tier requests-per-minute limit is not hit."""
    gap = LLM_CONFIG[prov]["gap"]
    with _RL["lock"]:
        now = time.time(); wait = max(0.0, _RL["next"] - now); _RL["next"] = max(now, _RL["next"]) + gap
    if wait: time.sleep(wait)

def _api_msg(r):
    try:
        j = r.json(); e = j.get("error", j) if isinstance(j, dict) else j
        return (e.get("message") if isinstance(e, dict) else str(e)) or r.text[:200]
    except Exception:
        return r.text[:200]

def call_llm(prompt, key, max_tokens=8192, temperature=0.6):
    """One request to Gemini or Groq. Returns the model's text. Retries on rate limits / temporary errors."""
    prov = detect_provider(key); cfg = LLM_CONFIG[prov]
    custom = os.environ.get("LLM_MODEL")
    if custom: models = [custom]
    else:
        first = _MODEL_OK.get(prov)
        models = ([first] if first else []) + [m for m in cfg["models"] if m != first]       # keep the other models as fall-backs
        models = [m for m in models if m not in _MODEL_BAD] or models
    last, quota = "", False
    for model in models:
        for attempt in range(3):
            _pace(prov)
            try:
                if prov == "gemini":
                    gc = {"temperature": temperature, "maxOutputTokens": max_tokens, "responseMimeType": "application/json"}
                    if "2.5-flash" in model: gc["thinkingConfig"] = {"thinkingBudget": 0}
                    r = requests.post(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                                      headers={"x-goog-api-key": key, "Content-Type": "application/json"},
                                      json={"contents": [{"role": "user", "parts": [{"text": prompt}]}], "generationConfig": gc}, timeout=180)
                else:
                    r = requests.post("https://api.groq.com/openai/v1/chat/completions",
                                      headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
                                      json={"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": temperature,
                                            "max_tokens": min(max_tokens, 8000), "response_format": {"type": "json_object"}}, timeout=180)
            except requests.RequestException as e:
                last = f"network error: {e}"; time.sleep(3 * (attempt + 1)); continue
            if r.status_code == 200:
                try:
                    d = r.json()
                    text = d["candidates"][0]["content"]["parts"][0]["text"] if prov == "gemini" else d["choices"][0]["message"]["content"]
                except Exception:
                    last = "the AI returned an empty answer"; time.sleep(2); continue
                _MODEL_OK[prov] = model
                return text
            msg = _api_msg(r)
            if r.status_code == 404:
                last = f"model '{model}' not found ({msg})"; break                      # try the next model name
            if r.status_code in (400, 401, 403):
                raise LLMError(f"{prov.title()} rejected the request ({r.status_code}): {msg}", fatal=True)
            if r.status_code in (429, 500, 502, 503, 504):
                quota = quota or r.status_code == 429
                last = f"{prov.title()} busy or rate-limited ({r.status_code}): {msg[:120]}"
                if r.status_code == 429 and re.search(r"per ?day|daily|PerDay", msg, re.I):
                    _MODEL_BAD.add(model); break                                   # daily quota of this model is gone -> next model
                try: wait = float(r.headers.get("Retry-After", ""))
                except ValueError: wait = 8 * (attempt + 1)
                time.sleep(min(60, max(wait, 5))); continue
            last = f"{prov.title()} error {r.status_code}: {msg[:160]}"; break
    raise LLMError(last or "AI request failed", fatal=quota or "not found" in last)

def _salvage_objects(t):
    """Pull every complete {...} question object out of damaged JSON (unescaped quotes, missing commas, cut-off text)."""
    start = t.find("[")
    if start < 0: start = t.find('"questions"')
    if start < 0: return []
    out, depth, in_str, esc, beg = [], 0, False, False, -1
    for i in range(start + 1, len(t)):
        ch = t[i]
        if in_str:
            if esc: esc = False
            elif ch == "\\": esc = True
            elif ch == '"': in_str = False
            continue
        if ch == '"': in_str = True
        elif ch == "{":
            if depth == 0: beg = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and beg >= 0:
                try: out.append(json.loads(t[beg:i + 1], strict=False))
                except json.JSONDecodeError: pass
                beg = -1
    return out

def _parse_json(text):
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", (text or "").strip(), flags=re.I)
    d = None
    for cand in (t, (re.search(r"\{.*\}|\[.*\]", t, re.S) or [None])[0] if re.search(r"\{.*\}|\[.*\]", t, re.S) else None):
        if not cand: continue
        try: d = json.loads(cand, strict=False); break          # strict=False accepts raw line breaks inside strings (code snippets)
        except json.JSONDecodeError: continue
    if d is None: d = _salvage_objects(t)                       # keep every complete question, drop only the broken one
    if not d: raise LLMError("the AI returned text that is not valid JSON")
    if isinstance(d, dict): d = d.get("questions") or next((v for v in d.values() if isinstance(v, list)), [])
    return d if isinstance(d, list) else []

_LABEL_RE = re.compile(r"^\s*(?:\(\s*[a-hA-H]\s*\)|[a-hA-H]\)|[a-hA-H]\.(?=\s)|\d+[.)](?=\s))\s*")

def _strip_label(t):
    """'a) text' / '(b) text' / 'c. text' -> 'text' (also repeated labels like 'a) a) text'), so a part is never labelled twice."""
    t = str(t).strip()
    while True:
        n = _LABEL_RE.sub("", t, count=1)
        if n == t or not n.strip(): return t
        t = n

def _norm_parts(p):
    """parts may arrive as a list, a JSON string, or one-per-line text -> clean list of strings WITHOUT their a) b) c) labels."""
    if isinstance(p, (list, tuple)): return [_strip_label(x) for x in p if str(x).strip()]
    if isinstance(p, str):
        s = p.strip()
        if s.startswith("["):
            try: return _norm_parts(json.loads(s))
            except Exception: pass
        return [_strip_label(l) for l in s.splitlines() if l.strip()]
    return []

def _clean_item(it, unit):
    """Validate one question coming back from the AI. Returns a question dict or None."""
    if not isinstance(it, dict): return None
    q = str(it.get("question") or "").strip()
    lv = str(it.get("bloom_level") or "").strip().title().replace("Analysing", "Analyzing")
    typ = norm_type(it.get("question_type"))
    if lv not in LEVELS or typ not in VALID_TYPES or len(q) < 15: return None
    parts = _norm_parts(it.get("parts"))
    if typ == "Long":
        if len(parts) >= 3: parts = parts[:6]           # multi-part form: stem + parts
        elif len(parts) in (1, 2):                      # too few parts -> fold them into the question text
            q = (q.rstrip() + " " + " ".join(parts)).strip(); parts = []
        if not parts and len(q) < 110: return None      # single form must be a real 4-5 line question, not a one-liner
    else:
        parts = []
    ans = it.get("answer", "")
    if isinstance(ans, list): ans = "\n".join(str(a) for a in ans)
    elif isinstance(ans, dict): ans = "\n".join(f"{k}) {v}" for k, v in ans.items())
    return dict(question=q, parts=parts, answer=str(ans or "").strip()[:3000], options=[], unit=unit,
                topic=(str(it.get("topic") or "").strip()[:80] or unit), bloom_level=lv,
                verb=q.split()[0].strip(".,:;?"), question_type=typ, marks=TYPE_MARKS[typ])

# ---------- prompt ----------
EXAMPLE_BLOCK = r'''STYLE EXAMPLES (a DIFFERENT subject - copy the clear, simple, easy-to-medium level and style, never the content):
Very Short (1 mark):
  "Define JSON."
  "List any two features of Node.js."
  "Write the npm command to install Express."
  "State the purpose of the package.json file."
Short (2 marks):
  "What is a callback function in Node.js? Write one simple example."
  "Consider the following code:\nconsole.log('A');\nsetTimeout(() => console.log('B'), 0);\nconsole.log('C');\nWrite the output of the program."
  "Write any two differences between HTTP and HTTPS."
Long (10 marks) = a stem plus parts:
  stem: "A college wants to build a simple Node.js application to show student details. Using npm, perform the following tasks:"
  parts: ["Write the command to create a package.json file.", "Write the command to install the Express package.", "Write a simple Express code to display \"Welcome Students\" on the home page.", "State the purpose of the package.json file."]
  stem: "Consider the following Node.js program:\nconsole.log('Start');\nsetTimeout(() => {\n  console.log('Later');\n}, 1000);\nconsole.log('End');\nAnswer the following:"
  parts: ["Write the output of the program.", "Explain why 'End' is printed before 'Later'.", "Define a callback function and name the callback used in this program.", "Write a Node.js code using fs.readFile() to read a file using a callback."]
Long (10 marks) = SINGLE form (one question of 4-5 lines, "parts": []):
  "A shopping website keeps all customer passwords as plain text in its database. Explain why this is risky and how storing hashed passwords reduces the risk. Give one simple example of how hashing is used when a user logs in."
  "A small library wants to keep records of its books. Explain why MongoDB can be used for this purpose, and write the commands to insert one book and to display all the books."
'''

STYLE_RULES = {
    "Theory": "THEORY questions: definitions, differences, working, components, advantages/limitations, use-cases. For technical subjects add a short code snippet, command, syntax or formula wherever it makes the question more precise.",
    "Scenario": "SCENARIO questions: each one starts from a short, realistic situation that genuinely fits the topic (a real kind of application, organisation or system - never a random company), then gives a precise task. Use different situations for different questions.",
    "Programming": "PROGRAMMING questions: write a program/query/command, predict the output of a given snippet (put the full snippet inside the question text), find and fix an error, trace execution, or complete code. Use the language/tools of the subject (infer them from the syllabus; otherwise Python, C or Java).",
}
FORMAT_RULES = {
    "Very Short": "VERY SHORT (1 mark): one simple sentence (at most two), answerable in 1 minute in 1-2 lines. Direct and exact (for example: define a term; list two features; name the components; state the purpose of a command). \"parts\" must be [].",
    "Short": "SHORT (2 marks): answerable in 2-3 minutes. Good forms: explain a concept and give a simple example; a tiny code snippet (at most 5 lines) with ONE simple task such as writing its output; or write any two differences. \"parts\" must be [].",
    "Long": "LONG (10 marks): worth 10 marks. It comes in TWO forms. MULTI-PART form: \"question\" is the STEM (a short, simple scenario or a small code listing followed by an instruction) and \"parts\" is a list of 3 or 4 simple sub-questions that belong to that stem and together are worth 10 marks; do NOT write the letters a), b), c) inside the parts and do not number them. SINGLE form: \"question\" is ONE self-contained question of about 3 to 5 lines (a short simple scenario followed by one clear task such as explain, compare, write or justify) and \"parts\" must be []. Never write a single-form question as a bare one-liner."
}

def _build_prompt(subject, unit, title, topics, style, needs, ref, extra, avoid, batch_no, multi_n=None):
    """needs = {format: {bloom level: how many}} - one request can ask for several formats at once."""
    off = (batch_no * 3) % max(1, len(topics))
    topics_rot = topics[off:] + topics[:off]
    typs = [t for t in VALID_TYPES if needs.get(t)]
    spec = "\n".join(f"{t} ({TYPE_MARKS[t]} mark{'s' if TYPE_MARKS[t] > 1 else ''}):\n" +
                     "\n".join(f"- {n} question(s) at Bloom level \"{l}\"" for l, n in needs[t].items()) for t in typs)
    levels = {l for t in typs for l in needs[t]}
    verbs = "\n".join(f"- {l}: " + ", ".join(next(b for b in BLOOM if b["name"] == l)["verbs"][:10]) for l in LEVELS if l in levels)
    total = sum(sum(needs[t].values()) for t in typs)
    long_mix = ""
    if "Long" in typs:
        n_long = sum(needs["Long"].values())
        if multi_n is None:                                   # no exact split asked: alternate the two forms
            multi = (n_long + batch_no % 2) // 2
            long_mix = (f"\nLONG QUESTIONS - MIX THE TWO FORMS: of the {n_long} Long question(s), exactly {multi} must be MULTI-PART (stem + 3 to 5 parts) and exactly {n_long - multi} must be SINGLE form "
                        "(one question of 4 to 5 lines with \"parts\": []). Alternate between the two forms - do not make them all multi-part.")
        else:                                                 # exact split chosen by the faculty
            multi = max(0, min(int(multi_n), n_long)); single = n_long - multi
            if multi == 0:
                long_mix = (f"\nLONG QUESTIONS - ALL {n_long} must be DIRECT questions: each one is a SINGLE self-contained question of 4 to 5 lines (a short simple scenario or code, then one clear task) "
                            "with \"parts\": [] . Do NOT write any sub-questions or a), b), c) parts for any Long question.")
            elif single == 0:
                long_mix = f"\nLONG QUESTIONS - ALL {n_long} must be MULTI-PART: each has a short stem in \"question\" and 3 or 4 sub-questions in \"parts\"."
            else:
                long_mix = (f"\nLONG QUESTIONS - EXACT SPLIT SET BY THE FACULTY: of the {n_long} Long question(s), EXACTLY {multi} must be MULTI-PART (a short stem in \"question\" plus 3 or 4 sub-questions in \"parts\") "
                            f"and EXACTLY {single} must be DIRECT: one single self-contained question of 4 to 5 lines with \"parts\": [] and no sub-questions at all. Do not change these two numbers.")
    p = [f"You are a senior university professor setting a B.Tech (Information Technology) examination for KITS Warangal.",
         f"SUBJECT: {subject}\nUNIT: {unit} - {title}\nSYLLABUS TOPICS OF THIS UNIT (spread the questions evenly across them, in this priority order): " + "; ".join(topics_rot),
         "TASK: write exactly these exam questions:\n" + spec + f"\nTotal items in the JSON array: exactly {total}. Every item's question_type must be exactly one of: " + ", ".join(f'"{t}"' for t in typs) + " - the one of the group it belongs to. List all Very Short items first, then Short, then Long.",
         "FORMAT RULES:\n" + "\n".join(FORMAT_RULES[t] for t in typs) + long_mix, "STYLE: " + STYLE_RULES[style],
         "DIFFICULTY - EASY TO MEDIUM, FOR THE WHOLE CLASS: at least 85 out of 100 students who attended the lectures and studied the notes once must be able to answer EVERY question. "
         "Allowed: easy and medium questions only. Forbidden: hard, tricky or trap questions, obscure details, long multi-concept problems, advanced optimisation, edge cases and heavy 'critically evaluate' essays. "
         "Use plain, simple English and short sentences (no rare words). Code snippets: at most 5 lines, basic syntax from the notes, one idea per snippet. "
         "Higher Bloom levels must still stay simple: Analyzing = compare two things or find the cause using the notes; Evaluating = choose between two options and give simple reasons; "
         "Creating = write or design something SMALL (a short command, a few lines of code, a simple table or diagram), never a full system. "
         "Before writing each question ask yourself: 'Would at least 85% of the students who studied this unit solve it?' If not, make it simpler.",
         "NO OVERLAP: every question must test a DIFFERENT point. Two questions must never be about the same concept, command, code snippet or example, even if the wording or the format (Very Short / Short / Long) or the Bloom level is different. "
         "Plan a different sub-topic for each question before writing, and cover all the syllabus topics given above evenly.",
         "BLOOM LEVEL VERBS to use at the start of the questions of each level:\n" + verbs,
         EXAMPLE_BLOCK]
    if extra.strip(): p.append("FACULTY NOTES (follow these): " + extra.strip())
    if ref: p.append("REFERENCE TEXT from the prescribed textbook (base the facts, terms, syntax and examples on it; never copy sentences and never write 'according to the textbook'):\n" + ref)
    else: p.append("No textbook was supplied: use your own accurate knowledge of these syllabus topics.")
    if avoid: p.append("ALREADY WRITTEN - do not repeat, rephrase or overlap with any of these (choose different concepts):\n" + "\n".join("- " + a for a in avoid[-150:]))
    p.append("QUALITY RULES:\n"
             "1. Be specific and unambiguous: name the exact concept, function, command, syntax, algorithm or situation. A bare \"Explain X in detail\" is NOT acceptable.\n"
             "2. Stay inside this unit's syllabus. Everything must be technically correct and easy-to-medium: answerable by at least 85% of the students who studied the unit.\n"
             "3. The action verb and the thinking required must really match the stated Bloom level.\n"
             "4. Every question must be self-contained: if it refers to code, put the complete code inside the question text (use \\n for line breaks).\n"
             "5. Vary the sub-topics and the wording; do not start many questions with the same verb. No duplicates and no overlapping questions.\n"
             "6. Never mention 'the syllabus', 'the unit', 'the textbook' or 'as discussed' inside a question.\n"
             "7. \"answer\" = a short, correct model answer or marking points (for Long: one line per part, starting with a), b), c)...).\n"
             "8. \"topic\" = the syllabus topic the question belongs to (copy it from the list above).")
    p.append('OUTPUT: return ONLY valid JSON, no markdown, in exactly this shape:\n'
             '{"questions":[{"bloom_level":"Applying","question_type":"' + typs[0] + '","topic":"<syllabus topic>","question":"<question text or Long stem>","parts":[],"answer":"<model answer>"}]}')
    return "\n\n".join(p)

# ---------- planning ----------
def level_plan(n, level, typ):
    """How many questions of each Bloom level for one format."""
    if level == "Each Level": return {l: n for l in LEVELS}
    if level in LEVELS:       return {level: n}
    order = ["Applying", "Analyzing", "Creating", "Evaluating", "Understanding", "Remembering"] if typ == "Long" else list(LEVELS)
    plan = {}
    for i in range(n):
        l = order[i % len(order)]; plan[l] = plan.get(l, 0) + 1
    return plan

def _slots(plan):
    rem, out = dict(plan), []
    while any(v > 0 for v in rem.values()):
        for l in LEVELS:
            if rem.get(l, 0) > 0: out.append(l); rem[l] -= 1
    return out

def _reference_text(chunks, limit):
    if not chunks: return ""
    paras = [" ".join(ch) for _, ch in chunks]
    total = sum(len(x) for x in paras)
    if total <= limit: return "\n".join(paras)
    stride, out, n = max(1, round(total / limit)), [], 0
    for x in paras[::stride]:
        if n + len(x) > limit: break
        out.append(x); n += len(x)
    return "\n".join(out)

_GENERIC = {"following", "given", "example", "examples", "simple", "write", "explain", "describe", "list", "state", "define", "code", "program", "using",
            "use", "used", "also", "give", "one", "two", "three", "four", "five", "between", "difference", "differences", "output", "answer", "task", "tasks",
            "scenario", "application", "applications", "student", "students", "college", "university", "company", "suitable", "basic", "short", "note"}
_BLOOM_WORDS = {v.lower() for b in BLOOM for v in b["verbs"]}

def _content_tokens(q):
    text = " ".join([q["question"]] + list(q.get("parts") or []))
    out = set()
    for w in re.findall(r"[A-Za-z][A-Za-z0-9_.\-]{2,}", text.lower()):
        w = w.strip(".-_")
        if len(w) < 3 or w in ENGLISH_STOP_WORDS or w in _GENERIC or w in _BLOOM_WORDS: continue
        out.add(w[:-1] if w.endswith("s") and len(w) > 4 else w)
    return out

def _overlaps(a, pool):
    """True when question tokens `a` largely repeat the points of an already accepted question in `pool`."""
    if len(a) < 2: return False
    for b in pool:
        inter = len(a & b)
        if not inter: continue
        if inter / len(a | b) >= 0.55 or (min(len(a), len(b)) >= 4 and inter / min(len(a), len(b)) >= 0.85): return True
    return False

def _to_direct(q):
    """A multi-part Long question that is not wanted as multi-part -> one direct question (stem + its tasks written as sentences)."""
    stem = re.sub(r"(?is)\s*(answer|perform|do|complete|attempt)\s+(all\s+)?the\s+following[^:.?!]*[:.]?\s*$", "", q["question"]).rstrip().rstrip(":")
    stem = stem if stem.endswith((".", "?", "!")) else stem + "."
    tail = " ".join(p.strip() if p.strip().endswith((".", "?", "!")) else p.strip() + "." for p in (q.get("parts") or []))
    q = dict(q); q["question"] = (stem + " " + tail).strip(); q["parts"] = []
    return q

CALL_WEIGHT = {"Very Short": 1, "Short": 2, "Long": 6}     # rough size of one question inside an AI answer

def generate_with_llm(units, style, limits, level, book_text, key, extra="", subject="", progress=None, multi=None):
    """Returns (questions, warnings). As few AI requests as possible (one per unit when it fits), run in parallel."""
    from concurrent.futures import ThreadPoolExecutor
    prog = progress or (lambda m: None)
    prov = detect_provider(key); cfg = LLM_CONFIG[prov]
    unit_chunks = build_unit_chunks(units, book_text) if book_text else {}
    tasks = []
    for unit in units:
        slots = []
        for typ in VALID_TYPES:
            want = int(limits.get(typ, 0))
            if want > 0: slots += [(typ, l) for l in _slots(level_plan(want, level, typ))]
        total = sum(CALL_WEIGHT[t] for t, _ in slots)
        k = max(1, math.ceil(total / cfg["budget"])); per = total / k           # split a big unit into equal calls
        cur, w, made = {}, 0, 0
        for typ, l in slots:
            if cur and made < k - 1 and w + CALL_WEIGHT[typ] > per * 1.02:
                tasks.append([unit, cur, made, k]); made += 1; cur, w = {}, 0
            cur.setdefault(typ, Counter())[l] += 1; w += CALL_WEIGHT[typ]
        if cur: tasks.append([unit, cur, made, k])
        # how many of this unit's Long questions must have sub-questions: share them out over the unit's calls
        ut = [t for t in tasks if t[0] == unit]
        for t in ut: t.append(0)
        if multi is not None:
            L, M = int(limits.get("Long", 0)), min(int(multi), int(limits.get("Long", 0)))
            prev = done = 0
            for t in ut:
                done += sum(t[1]["Long"].values()) if "Long" in t[1] else 0
                cum = round(M * done / L) if L else 0
                t[4], prev = cum - prev, cum
    t0 = time.time()
    lock, stop = threading.Lock(), threading.Event()
    out, warns, seen, state, pools = [], [], set(), {"done": 0, "fatal": ""}, {}
    prog(f"AI is writing questions: 0/{len(tasks)} calls done")
    elapsed = lambda: f" · {int(time.time() - t0)}s"

    def run(task):
        unit, need, bno, ncalls, mrem = task
        if stop.is_set(): return
        u = units[unit]
        topics = [pretty(t) for t in dict.fromkeys(u["topics"]) if len(t.strip()) >= 3] or [u["title"]]
        if ncalls > 1 and len(topics) >= ncalls: topics = topics[bno::ncalls]          # calls of the same unit get DIFFERENT topics -> no overlap between them
        ref = _reference_text(unit_chunks.get(unit), cfg["ref_chars"])
        need = {t: Counter(c) for t, c in need.items()}
        asked, accepted = sum(sum(c.values()) for c in need.values()), 0
        last_err = ""
        for attempt in range(3):
            need = {t: Counter({l: n for l, n in c.items() if n > 0}) for t, c in need.items()}
            need = {t: c for t, c in need.items() if c}
            if not need or stop.is_set(): break
            with lock: avoid = [q["question"][:110].replace("\n", " ") for q in out if q["unit"] == unit]
            lrem_now = sum(need["Long"].values()) if need.get("Long") else 0
            m_now = None if multi is None else max(0, min(mrem, lrem_now))
            try:
                items = _parse_json(call_llm(_build_prompt(subject, unit, u["title"], topics, style, need, ref, extra, avoid, bno, m_now), key, max_tokens=cfg["max_out"]))
            except LLMError as e:
                if e.fatal:
                    with lock:
                        warns.append(f"{unit}: {e}"); state["fatal"] = state["fatal"] or str(e); stop.set()
                    break
                last_err = str(e); continue                    # bad JSON / empty answer: ask again
            for it in items:
                c = _clean_item(it, unit)
                if not c: continue
                nd = need.get(c["question_type"])
                if not nd or nd.get(c["bloom_level"], 0) <= 0: continue
                if multi is not None and c["question_type"] == "Long":     # keep EXACTLY the asked number with / without sub-questions
                    drem = sum(nd.values()) - mrem
                    if c["parts"]:
                        if mrem <= 0:
                            if drem <= 0: continue
                            c = _to_direct(c)                              # more sub-question items than wanted -> make it a direct question
                    elif drem <= 0: continue                               # only multi-part slots are left
                with lock:
                    k = _norm(c["question"]); tk = _content_tokens(c)
                    dup = k in seen or _overlaps(tk, pools.setdefault(unit, []))
                    if not dup: seen.add(k); pools[unit].append(tk); out.append(c)
                if dup: continue
                nd[c["bloom_level"]] -= 1; accepted += 1
                if multi is not None and c["question_type"] == "Long" and c["parts"]: mrem -= 1
            if accepted >= asked: break                                   # everything delivered; otherwise ask again for just the missing ones
        with lock:
            state["done"] += 1
            if accepted < asked and not stop.is_set(): warns.append(f"{unit}: asked for {asked}, only {accepted} could be generated" + (f" ({last_err})" if last_err else ""))
            prog(f"AI is writing questions: {state['done']}/{len(tasks)} calls done{elapsed()}")

    with ThreadPoolExecutor(max_workers=cfg["workers"]) as ex: list(ex.map(run, tasks))
    if not out and state["fatal"]: raise ValueError(state["fatal"])
    return out, warns

# ---------- start-up check ----------
print("AI key found - AI generation is ready (" + detect_provider(DEFAULT_KEY) + ")" if DEFAULT_KEY else
      "No saved AI key - paste your Gemini/Groq key on the Generate page (or add a Colab secret named LLM_KEY)")
print("✅ NLP engine ready")
# ============ CELL 4: FACULTY FEATURES ============
from collections import Counter, OrderedDict
from datetime import timezone

def _row(r):
    d = dict(r); d["options"] = json.loads(d["options"]) if d.get("options") else []; d["parts"] = _norm_parts(d.get("parts")); return d

def _insert_questions(rows, faculty_id, bank_id=None):
    n = 0
    with db() as c:
        for q in rows:
            dup = c.execute("SELECT 1 FROM questions WHERE lower(question)=lower(?) AND subject=? AND unit=?",
                            (q["question"], q["subject"], q["unit"])).fetchone()
            if dup: continue
            verb = q.get("verb") or (q["question"].split() or [""])[0].strip(".,:;?")
            c.execute("""INSERT INTO questions(question,answer,options,subject,unit,topic,bloom_level,verb,
                         question_type,marks,faculty_id,bank_id,qstyle,parts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (q["question"], q.get("answer", ""), json.dumps(q.get("options") or []), q["subject"],
                       q["unit"], q.get("topic", ""), q["bloom_level"], verb, q["question_type"],
                       TYPE_MARKS[q["question_type"]], faculty_id, bank_id, norm_style(q.get("qstyle")), json.dumps(_norm_parts(q.get("parts")))))
            n += 1
    return n

def _validate(q):
    if not q.get("question", "").strip():  raise ValueError("Question text is required.")
    if not q.get("subject", "").strip():   raise ValueError("Subject is required.")
    if not q.get("unit", "").strip():      raise ValueError("Unit is required.")
    if q.get("bloom_level") not in LEVELS:        raise ValueError("Bloom level must be one of: " + ", ".join(LEVELS) + ".")
    q["question_type"] = norm_type(q.get("question_type"))
    if q["question_type"] not in VALID_TYPES: raise ValueError("Format must be Very Short, Short or Long.")
    q["marks"] = TYPE_MARKS[q["question_type"]]          # Very Short=1, Short=2, Long=10

def _save_bank(faculty_id, title, subject, desc, filenames):
    with db() as c:
        cur = c.execute("INSERT INTO questionbank(title,subject,description,file,faculty_id,upload_date) VALUES(?,?,?,?,?,?)",
                        (title, subject, desc, ", ".join(filenames), faculty_id, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")))
        return cur.lastrowid

# ---------- FR4: upload syllabus + textbook -> auto-generate questions ----------
def parse_unit_filter(s):
    """'1,3' / 'unit 2' / '1-3' / 'II'  ->  {'Unit 1','Unit 2',...}. Empty = all units."""
    out = set()
    for t in re.split(r"[,\s;]+", (s or "").strip()):
        t = re.sub(r"(?i)^unit-?", "", t).strip().lower()
        if not t: continue
        m = re.fullmatch(r"(\d+)-(\d+)", t)
        if m: out |= {f"Unit {i}" for i in range(int(m.group(1)), int(m.group(2)) + 1)}
        else: out.add(f"Unit {ROMAN.get(t, t)}")
    return out

def upload_syllabus_textbook(token, subject, title, syl_files, book_files=None,
                             limits=None, only_units=None, replace=True, level="All Levels", style="Theory",
                             engine="offline", api_key="", extra="", progress=None, multi=None):
    """syl_files / book_files = lists of (filename, bytes) - one or MANY syllabus and textbook files.
    limits = {"Very Short": n, "Short": n, "Long": n}  -> n questions per unit for each format (None = keep everything)."""
    book_files = book_files or []
    p = require_role(token, "Faculty")
    subject = subject.strip()
    if not subject: raise ValueError("Enter the subject name.")
    if level not in ("All Levels", "Each Level") and level not in LEVELS: raise ValueError("Choose a valid Bloom level.")
    if style not in STYLES: raise ValueError("Choose a question style: Theory, Scenario or Programming.")
    if limits is not None:
        limits = {t: max(0, int(limits.get(t, 0))) for t in VALID_TYPES}
        if not any(limits.values()): raise ValueError("Set at least one format (Very Short / Short / Long) to more than 0.")
    if multi is not None:
        multi = max(0, int(multi))
        if limits is not None and multi > limits["Long"]: raise ValueError(f"Long questions with sub-questions ({multi}) cannot be more than the total Long questions ({limits['Long']}).")
    if not syl_files: raise ValueError("Please choose at least one syllabus file.")
    # "References" between files = a stop-heading, so loose lines at the top of file 2 never leak into the last unit of file 1
    syl_text = "\n\nReferences\n\n".join(read_file(n, b) for n, b in syl_files)
    units = parse_syllabus(syl_text)
    if only_units:
        units = {u: v for u, v in units.items() if u in only_units}
        if not units: raise ValueError("None of the units you typed were found in the syllabus. Found: " + ", ".join(parse_syllabus(syl_text)))
    if style != "Theory" and engine != "ai": book_files = []     # Scenario / Programming questions are built from the syllabus topics
    book_texts, skipped = [], []
    for n, b in book_files:
        t = read_file(n, b)
        (book_texts if len(t.split()) >= 100 else skipped).append(t if len(t.split()) >= 100 else n)
    if book_files and not book_texts:
        raise ValueError("Could not read enough text from the textbook(s): " + ", ".join(skipped) + " (scanned PDF?). Use text-based PDF/DOCX/TXT files, or upload only the syllabus.")
    has_book = bool(book_texts)
    shortfalls = []
    if engine == "ai":
        key = get_llm_key(api_key)
        if not key: raise ValueError("AI mode needs an API key. Paste a free Gemini (AIza...) or Groq (gsk_...) key in the form, or choose 'Offline templates'.")
        if limits is None: limits = {"Very Short": 20, "Short": 10, "Long": 5}
        qs, shortfalls = generate_with_llm(units, style, limits, level, "\n\n".join(book_texts), key, extra or "", subject, progress, multi)
        if not qs: raise ValueError("The AI did not return any usable questions. " + " ".join(shortfalls[:2]))
    elif style != "Theory":
        qs = generate_applied(units, style)
        if not qs: raise ValueError("No topics found in the syllabus. Use lines like 'Unit 1: Topic, Topic'.")
    elif has_book:
        book_text = "\n\n".join(book_texts)
        qs = generate_all(units, book_text)
        covered = {q["unit"] for q in qs}
        qs += generate_from_syllabus({u: v for u, v in units.items() if u not in covered})   # units the textbook did not cover
        if not qs: raise ValueError("No questions could be generated. Check that the syllabus topics match the textbook content.")
    else:
        qs = generate_from_syllabus(units)
        if not qs: raise ValueError("No topics found in the syllabus. Use lines like 'Unit 1: Topic, Topic'.")
    if limits is not None and engine != "ai":
        qs, shortfalls = select_limited(qs, limits, list(units), level)
    uploads = list(syl_files) + list(book_files)
    for fn, data in uploads:
        open(os.path.join(UPLOAD_DIR, f"{int(time.time())}_{os.path.basename(fn)}"), "wb").write(data)
    removed = 0
    if replace:     # drop this faculty's earlier AUTO-GENERATED questions for the subject (uploaded CSV/JSON banks are untouched)
        with db() as c:
            ids = [r[0] for r in c.execute("SELECT id FROM questionbank WHERE subject=? AND faculty_id=? AND description LIKE 'Auto-generated%'", (subject, p["uid"]))]
            for i in ids:
                removed += c.execute("DELETE FROM questions WHERE bank_id=? AND COALESCE(qstyle,'Theory')=?", (i, style)).rowcount   # same style only
                if not c.execute("SELECT 1 FROM questions WHERE bank_id=?", (i,)).fetchone(): c.execute("DELETE FROM questionbank WHERE id=?", (i,))
            c.execute("DELETE FROM subject_units WHERE subject=? AND unit NOT IN (SELECT unit FROM questions WHERE subject=?)", (subject, subject))
    desc = ("Auto-generated from syllabus + textbook" if has_book else "Auto-generated from syllabus only") if style == "Theory" else f"Auto-generated {style} questions from syllabus"
    if engine == "ai": desc = f"Auto-generated (AI) {style} questions" + (" from syllabus + textbook" if has_book else " from syllabus")
    bank_id = _save_bank(p["uid"], title or (subject if style == "Theory" else f"{subject} – {style}"), subject, desc, [n for n, _ in uploads])
    for q in qs: q["subject"] = subject; q["qstyle"] = style
    with db() as c:
        for u, v in units.items():
            c.execute("INSERT OR REPLACE INTO subject_units(subject,unit,title) VALUES(?,?,?)", (subject, u, v["title"]))
    added = _insert_questions(qs, p["uid"], bank_id)
    return {"engine": engine, "syllabus_only": not has_book, "units": {u: v["topics"] for u, v in units.items()}, "generated": len(qs), "added": added,
            "removed": removed, "style": style, "n_syllabus": len(syl_files), "n_books": len(book_files) - len(skipped), "skipped_files": skipped, "limits": limits, "shortfalls": shortfalls, "level": level,
            "questions": sorted(qs, key=lambda q: (_unit_key(q["unit"]), LEVEL_ORDER.get(q["bloom_level"], 9), VALID_TYPES.index(q["question_type"])))[:1000],
            "by_level": {l: sum(1 for q in qs if q["bloom_level"] == l) for l in LEVELS},
            "by_type": dict(Counter(q["question_type"] for q in qs)),
            "with_parts": sum(1 for q in qs if q["question_type"] == "Long" and q.get("parts"))}

# ---------- FR4: upload a ready-made question-bank file (CSV / JSON) ----------
def upload_question_file(token, subject, title, desc, fname, data):
    p = require_role(token, "Faculty")
    ext = fname.lower().rsplit(".", 1)[-1]
    if ext == "json":    rows = json.loads(data.decode("utf-8-sig"))
    elif ext == "csv":   rows = list(csv.DictReader(io.StringIO(data.decode("utf-8-sig"))))
    else: raise ValueError("Upload a .csv or .json file.")
    good, errors = [], []
    for i, r in enumerate(rows, 1):
        r = {k.strip().lower(): (v.strip() if isinstance(v, str) else v) for k, v in r.items()}
        r.setdefault("subject", subject)
        r["subject"] = r["subject"] or subject
        r["qstyle"] = norm_style(r.get("style") or r.get("qstyle"))
        r["question_type"] = norm_type(r.get("question_type") or r.get("questiontype") or r.get("format") or "Short")
        r["bloom_level"] = (r.get("bloom_level") or r.get("level") or r.get("bloom") or "").strip().title()
        if isinstance(r.get("options"), str): r["options"] = [o.strip() for o in r["options"].split("|") if o.strip()]
        r["parts"] = _norm_parts(r["parts"].split("|")) if isinstance(r.get("parts"), str) else _norm_parts(r.get("parts"))
        try: _validate(r); good.append(r)
        except ValueError as e: errors.append(f"Row {i}: {e}")
    bank_id = _save_bank(p["uid"], title or fname, subject, desc, [fname])
    open(os.path.join(UPLOAD_DIR, f"{int(time.time())}_{os.path.basename(fname)}"), "wb").write(data)
    return {"added": _insert_questions(good, p["uid"], bank_id), "errors": errors}

# ---------- FR5-FR7: add / edit / delete ----------
def add_question(token, **q):
    p = require_role(token, "Faculty"); _validate(q)
    if isinstance(q.get("options"), str): q["options"] = [o.strip() for o in q["options"].split("|") if o.strip()]
    if _insert_questions([q], p["uid"]) == 0: raise ValueError("This question already exists.")

def _own(c, uid, qid):
    r = c.execute("SELECT * FROM questions WHERE id=?", (qid,)).fetchone()
    if not r: raise ValueError("Question not found.")
    if r["faculty_id"] != uid: raise PermissionError("You can only change questions you uploaded.")
    return dict(r)

def edit_question(token, qid, **fields):
    p = require_role(token, "Faculty")
    with db() as c:
        cur = _own(c, p["uid"], qid)
        cur.update({k: v for k, v in fields.items() if v is not None})
        if isinstance(cur.get("options"), str) and not cur["options"].startswith("["):
            cur["options"] = [o.strip() for o in cur["options"].split("|") if o.strip()]
        elif isinstance(cur.get("options"), str): cur["options"] = json.loads(cur["options"])
        _validate(cur)
        c.execute("""UPDATE questions SET question=?,answer=?,options=?,subject=?,unit=?,topic=?,bloom_level=?,verb=?,
                     question_type=?,marks=?,parts=? WHERE id=?""",
                  (cur["question"], cur.get("answer", ""), json.dumps(cur.get("options") or []), cur["subject"],
                   cur["unit"], cur.get("topic", ""), cur["bloom_level"], (cur["question"].split() or [""])[0].strip(".,:;?"),
                   cur["question_type"], cur["marks"], json.dumps(_norm_parts(cur.get("parts"))), qid))

def delete_question(token, qid):
    p = require_role(token, "Faculty")
    with db() as c:
        _own(c, p["uid"], qid); c.execute("DELETE FROM questions WHERE id=?", (qid,))

def list_questions(token, subject=None, unit=None, level=None, qtype=None, search=None, own_only=True):
    p = verify_token(token)
    if not p: raise PermissionError("Session expired. Please log in again.")
    sql, args = "SELECT * FROM questions WHERE 1=1", []
    if own_only and p["role"] == "Faculty": sql += " AND faculty_id=?"; args.append(p["uid"])
    for col, v in (("subject", subject), ("unit", unit), ("bloom_level", level), ("question_type", qtype)):
        if v and v != "All": sql += f" AND {col}=?"; args.append(v)
    if search: sql += " AND (question LIKE ? OR topic LIKE ?)"; args += [f"%{search}%"] * 2
    with db() as c:
        return [_row(r) for r in c.execute(sql + " ORDER BY subject, unit, id", args)]

def get_subjects():
    with db() as c: return [r[0] for r in c.execute("SELECT DISTINCT subject FROM questions ORDER BY subject")]

def _unit_key(u): return [int(t) if t.isdigit() else t for t in re.split(r'(\d+)', u)]

def get_units(subject):
    with db() as c:
        us = {r[0] for r in c.execute("SELECT DISTINCT unit FROM questions WHERE subject=?", (subject,))}
        us |= {r[0] for r in c.execute("SELECT unit FROM subject_units WHERE subject=?", (subject,))}
    return sorted(us, key=_unit_key)

# ---------- dashboards ----------
def faculty_stats(token):
    p = require_role(token, "Faculty")
    with db() as c:
        q = lambda sql, *a: c.execute(sql, a).fetchall()
        total = q("SELECT COUNT(*) FROM questions WHERE faculty_id=?", p["uid"])[0][0]
        subjects = q("SELECT COUNT(DISTINCT subject) FROM questions WHERE faculty_id=?", p["uid"])[0][0]
        units = q("SELECT COUNT(DISTINCT subject||unit) FROM questions WHERE faculty_id=?", p["uid"])[0][0]
        lv = {r[0]: r[1] for r in q("SELECT bloom_level, COUNT(*) FROM questions WHERE faculty_id=? GROUP BY bloom_level", p["uid"])}
        ty = {r[0]: r[1] for r in q("SELECT question_type, COUNT(*) FROM questions WHERE faculty_id=? GROUP BY question_type", p["uid"])}
        banks = [dict(r) for r in q("""SELECT b.title, b.subject, b.upload_date, b.file,
                   (SELECT COUNT(*) FROM questions WHERE bank_id=b.id) AS n FROM questionbank b
                   WHERE b.faculty_id=? ORDER BY b.id DESC LIMIT 6""", p["uid"])]
    return {"total": total, "subjects": subjects, "units": units, "banks": len(banks),
            "by_level": {l: lv.get(l, 0) for l in LEVELS}, "by_type": ty, "recent": banks}

# ---------- download: PDF / Word / Text ----------
# ---------- download: PDF / Word / Text  (layout like a university QUESTION BANK) ----------
BLOOM_CODE = {"Remembering": "R", "Understanding": "U", "Applying": "AP", "Analyzing": "AN", "Evaluating": "E", "Creating": "C"}
SECTION_TITLES = {"Very Short": "Very Short Questions", "Short": "Short Questions", "Long": "Long Questions"}

def _unit_label(u):
    u = (u or "").strip()
    if not u or u.lower() in ("all units", "all"): return "All Units"
    return ", ".join(re.sub(r"(?i)^unit\s*", "", p.strip()) for p in u.split(",") if p.strip())

def _doc_model(qs, meta):
    """-> (header lines, [(section title, [item, ...])]).  Each format restarts its numbering at 1."""
    head = ["QUESTION BANK", f"Subject : {meta.get('subject', '')}", f"Unit : {_unit_label(meta.get('units'))}"]
    sections = []
    for typ in VALID_TYPES:
        items = []
        for q in qs:
            if q.get("question_type") != typ: continue
            sub = [str(x) for x in _norm_parts(q.get("parts"))] + [_strip_label(o) for o in (q.get("options") or [])]
            items.append(dict(no=len(items) + 1, text=str(q.get("question", "")).strip(), sub=sub,
                              code=BLOOM_CODE.get(q.get("bloom_level"), ""), answer=(q.get("answer") or "").strip()))
        if items: sections.append((SECTION_TITLES[typ], items))
    return head, sections

# Helvetica character widths (1/1000 em) for ASCII 32..126 - used to wrap lines and right-align the Bloom code exactly
_HELV = [278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278] + [556]*10 + [278,278,584,584,584,556,1015] + \
        [667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,667,778,722,667,611,722,667,944,667,667,611] + \
        [278,278,278,469,556,333] + [556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,556,556,333,500,278,556,500,722,500,500,500] + \
        [334,260,334,584]
_HELVB_UP = dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ", [722,722,722,722,667,611,778,722,278,556,722,611,833,722,778,667,778,722,667,611,722,667,944,667,667,611]))

# ---- PDF font: Book Antique (if installed) -> TeX Gyre Pagella (Palatino clone, same look) -> Helvetica fallback ----
_PDF_FONTS = {}
def _pdf_fonts():
    """-> {'reg': info, 'bold': info} with embedded-font data, or {} when no Palatino-type font exists on this machine."""
    if _PDF_FONTS.get("done"): return _PDF_FONTS.get("fonts", {})
    _PDF_FONTS["done"] = True
    import os
    try:
        from fontTools.ttLib import TTFont
    except Exception:
        return {}
    roots = ["/usr/share/fonts", "/usr/local/share/fonts", "/usr/share/texmf/fonts", "/usr/share/texlive", os.path.expanduser("~/.fonts"), "/content", "."]
    found = {}
    for root in roots:
        for dp, _, fns in os.walk(root):
            for fn in fns: found.setdefault(fn.lower(), os.path.join(dp, fn))
    pick = lambda names: next((found[n] for n in names if n in found), None)
    paths = {"reg": pick(["bkant.ttf", "bookantiqua.ttf", "book antiqua.ttf", "texgyrepagella-regular.otf"]),
             "bold": pick(["antquab.ttf", "bookantiqua-bold.ttf", "texgyrepagella-bold.otf"])}
    if not paths["reg"]: return {}
    paths["bold"] = paths["bold"] or paths["reg"]
    fonts = {}
    for k, p in paths.items():
        f = TTFont(p); cmap = f.getBestCmap(); upm = f["head"].unitsPerEm; hm = f["hmtx"]
        w = []
        for code in range(32, 256):
            g = cmap.get(ord(bytes([code]).decode("cp1252", "replace")))
            w.append(int(round(hm[g][0] * 1000.0 / upm)) if g else 0)
        hd = f["head"]; os2 = f["OS/2"] if "OS/2" in f else None
        asc = int(round(f["hhea"].ascent * 1000.0 / upm)); dsc = int(round(f["hhea"].descent * 1000.0 / upm))
        cap = int(round(getattr(os2, "sCapHeight", 0) * 1000.0 / upm)) or int(asc * 0.7) if os2 else int(asc * 0.7)
        raw = open(p, "rb").read()
        fonts[k] = dict(widths=w, data=raw, cff=raw[:4] == b"OTTO", name=re.sub(r"[^A-Za-z0-9-]", "", f["name"].getDebugName(6) or ("BookAntique-" + k)),
                        bbox=[int(round(v * 1000.0 / upm)) for v in (hd.xMin, hd.yMin, hd.xMax, hd.yMax)], asc=asc, dsc=dsc, cap=cap)
    _PDF_FONTS["fonts"] = fonts
    return fonts

def _tw(text, size, bold=False):
    fonts = _pdf_fonts()
    if fonts:
        w = fonts["bold" if bold else "reg"]["widths"]
        tot = 0
        for ch in text:
            b = ch.encode("cp1252", "replace")[0]
            tot += w[b - 32] if 32 <= b <= 255 else 500
        return tot * size / 1000.0
    if bold: return sum(_HELVB_UP.get(ch, 600) for ch in text) * size / 1000.0
    return sum(_HELV[ord(ch) - 32] if 32 <= ord(ch) <= 126 else 556 for ch in text) * size / 1000.0

def _wrap(text, size, maxw):
    """Greedy word wrap with real font widths; keeps the line breaks of code snippets."""
    lines = []
    for seg in str(text).split("\n"):
        cur = ""
        for w in seg.split(" "):
            trial = (cur + " " + w) if cur else w
            if _tw(trial, size) <= maxw: cur = trial; continue
            if cur: lines.append(cur)
            while _tw(w, size) > maxw and len(w) > 1:
                k = max(1, int(len(w) * maxw / _tw(w, size))); lines.append(w[:k]); w = w[k:]
            cur = w
        lines.append(cur)
    return lines

def make_txt(qs, meta, answers=False):
    import textwrap
    head, sections = _doc_model(qs, meta); W = 78
    out = [head[0], "=" * W, head[1], head[2]]
    def block(prefix, text, indent, code=""):
        lines = []
        for seg in str(text).split("\n"): lines += textwrap.wrap(seg, W - indent - 6, replace_whitespace=False) or [""]
        res = [(prefix if i == 0 else " " * indent) + ln for i, ln in enumerate(lines)]
        if code: res[-1] += f"  [{code}]"                                  # Bloom code right after the question
        return res
    for title, items in sections:
        out += ["", title, "-" * len(title)]
        for it in items:
            out += block(f"{it['no']}. ", it["text"], len(f"{it['no']}. "), it["code"])
            for j, sp in enumerate(it["sub"]):
                out += block(f"   {'abcdefgh'[j % 8]}) ", sp, 6)
    if answers:
        out += ["", "=" * W, "ANSWER KEY / REFERENCE POINTS", "=" * W]
        for title, items in sections:
            out += ["", title]
            for it in items: out += block(f"{it['no']}. ", it["answer"] or "(no reference answer stored)", len(f"{it['no']}. "))
    return "\n".join(out).encode("utf-8")

def make_docx(qs, meta, answers=False):
    import docx
    from docx.shared import Inches, Pt, RGBColor
    from docx.oxml.ns import qn
    d = docx.Document()
    nf = d.styles["Normal"].font; nf.name = "Book Antiqua"; nf.size = Pt(11)
    for rf in d.styles.element.xpath("w:docDefaults/w:rPrDefault/w:rPr/w:rFonts") + [d.styles["Normal"].element.rPr.rFonts]:
        for att in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
            if rf.get(qn(att)) is not None: del rf.attrib[qn(att)]          # drop the theme font (Cambria) so Book Antiqua is really used
        for att in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"): rf.set(qn(att), "Book Antiqua")
    head, sections = _doc_model(qs, meta)
    r = d.add_paragraph().add_run(head[0]); r.bold = True; r.font.size = Pt(14)
    for ln in head[1:]: d.add_paragraph(ln).paragraph_format.space_after = Pt(0)
    def para(label, text, left, code="", after=2):
        p = d.add_paragraph(); pf = p.paragraph_format
        pf.left_indent, pf.first_line_indent, pf.space_after = Inches(left), Inches(-0.35), Pt(after)
        pf.tab_stops.add_tab_stop(Inches(left))
        p.add_run(label + "\t")
        for k, seg in enumerate(str(text).split("\n")):
            if k: p.add_run().add_break()
            p.add_run(seg)
        if code:                                                                   # Bloom code [AP]: dark, right after the question text
            rc = p.add_run("  [" + code + "]"); rc.font.color.rgb = RGBColor(0x26, 0x26, 0x26)
    for title, items in sections:
        h = d.add_paragraph(); h.paragraph_format.space_before = Pt(14); rr = h.add_run(title); rr.bold = True; rr.font.size = Pt(14)
        for it in items:
            para(f"{it['no']}.", it["text"], 0.35, it["code"], 8 if not it["sub"] else 2)
            for j, sp in enumerate(it["sub"]):
                last = j == len(it["sub"]) - 1
                para(f"{'abcdefgh'[j % 8]})", sp, 0.75, "", 8 if last else 2)
    if answers:
        d.add_page_break(); r = d.add_paragraph().add_run("Answer Key / Reference Points"); r.bold = True; r.font.size = Pt(14)
        for title, items in sections:
            r = d.add_paragraph().add_run(title); r.bold = True; r.font.size = Pt(14)
            for it in items: para(f"{it['no']}.", it["answer"] or "(no reference answer stored)", 0.35)
    b = io.BytesIO(); d.save(b); return b.getvalue()

def make_html(qs, meta, answers=False):
    """Print-ready page. The BROWSER draws it with Book Antiqua installed on the user's own PC and 'Save as PDF' embeds that real font."""
    import html as H
    head, sections = _doc_model(qs, meta)
    e = lambda t: H.escape(str(t))
    name = re.sub(r"[^A-Za-z0-9]+", "_", f"Question_Bank_{meta.get('subject', '')}_{_unit_label(meta.get('units'))}").strip("_")
    def item(it, ans=False):
        txt = e(it["answer"] or "(no reference answer stored)") if ans else e(it["text"])
        code = "" if ans or not it["code"] else f' <span class="bc">[{e(it["code"])}]</span>'
        subs = "" if ans else "".join(f'<div class="sub"><span class="n">{"abcdefgh"[j % 8]})</span><div class="t">{e(sp)}</div></div>' for j, sp in enumerate(it["sub"]))
        return f'<div class="q"><span class="n">{it["no"]}.</span><div class="t">{txt}{code}</div></div>{subs}'
    body = f'<h1>{e(head[0])}</h1><p class="hd">{e(head[1])}<br>{e(head[2])}</p>'
    for title, items in sections: body += f'<h2>{e(title)}</h2>' + "".join(item(i) for i in items)
    if answers:
        body += '<h1 class="pb">Answer Key / Reference Points</h1>'
        for title, items in sections: body += f'<h2>{e(title)}</h2>' + "".join(item(i, True) for i in items)
    css = ('@page{size:A4;margin:0}*{box-sizing:border-box}table.pg{width:100%;border-collapse:collapse}table.pg td{padding:0 20mm}.sp{height:18mm}'
           'body{font-family:"Book Antiqua","Palatino Linotype",Palatino,"TeX Gyre Pagella",serif;font-size:11pt;line-height:1.35;color:#000;margin:0}'
           'h1,h2{font-size:14pt;font-weight:bold;margin:14pt 0 6pt}h1{margin-top:0}.hd{margin:0 0 4pt}'
           '.q,.sub{display:flex;gap:8pt;margin:0 0 6pt;page-break-inside:avoid}.q .n{width:26pt;flex:none}.sub{margin-left:26pt;margin-bottom:3pt}.sub .n{width:20pt;flex:none}'
           '.t{white-space:pre-wrap;flex:1}.bc{color:#262626}.pb{page-break-before:always}')
    return (f'<!DOCTYPE html><html><head><meta charset="utf-8"><title>{e(name)}</title><style>{css}</style></head><body><table class="pg"><thead><tr><td><div class="sp"></div></td></tr></thead><tbody><tr><td>{body}</td></tr></tbody><tfoot><tr><td><div class="sp"></div></td></tr></tfoot></table>'
            '<script>window.onload=function(){setTimeout(function(){window.print()},500)}</script></body></html>').encode("utf-8")

def make_pdf(qs, meta, answers=False):
    """Dependency-free PDF writer (A4, Book Antique / Palatino-type font embedded) with exact wrapping and a right-aligned Bloom code after each question."""
    _PDF_FONTS.clear()                                           # re-look for the font files on every download (so a late upload is picked up)
    esc = lambda t: t.encode("cp1252", "replace").decode("cp1252").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    L, R, TOP, BOT = 50, 545, 790, 55
    pages, cur = [], []; y = [TOP]
    def newpage():
        nonlocal cur
        if cur: pages.append(cur)
        cur = []; y[0] = TOP
    def text(x, t, font="F1", size=11, gray=None):
        g0, g1 = (f"{gray} g ", " 0 g") if gray is not None else ("", "")
        cur.append(f"{g0}BT /{font} {size} Tf {x:.1f} {y[0]:.1f} Td ({esc(t)}) Tj ET{g1}")
    def line_gap(g): y[0] -= g
    def need(h):
        if y[0] - h < BOT: newpage()
    head, sections = _doc_model(qs, meta)
    text(L, head[0], "F2", 14); line_gap(24)
    for ln in head[1:]: text(L, ln, "F1", 11); line_gap(17)
    SZ, LEAD = 11, 14.5
    def item_rows(it):
        """-> ([(x_number_or_None, label, x_text, line)], index of the last line of the question stem)."""
        rows = [(L, f"{it['no']}.", 72, ln) if i == 0 else (None, "", 72, ln) for i, ln in enumerate(_wrap(it["text"], SZ, 520 - 72))]
        stem_last = len(rows) - 1
        for j, sp in enumerate(it["sub"]):
            for i, ln in enumerate(_wrap(sp, SZ, 520 - 96)): rows.append((72 if i == 0 else None, f"{'abcdefgh'[j % 8]})" if i == 0 else "", 96, ln))
        return rows, stem_last
    def draw_item(it, size=SZ):
        rows, stem_last = item_rows(it); code = f"[{it['code']}]" if it["code"] else ""
        need(min(len(rows) * LEAD + 8, 640))
        for k, (xl, label, xt, ln) in enumerate(rows):
            if y[0] < BOT: newpage()
            if label: text(xl, label, "F1", size)
            text(xt, ln, "F1", size)
            if code and k == stem_last:                          # Bloom code [AP]: dark, right after the question itself (not after its parts)
                cx = xt + _tw(ln, size) + 7
                if cx + _tw(code, size) > R:                     # no room on this line -> start of the next line
                    line_gap(LEAD); need(LEAD); cx = xt
                text(cx, code, "F1", size, 0.15)
            line_gap(LEAD)
        line_gap(7)
    for title, items in sections:
        need(60); line_gap(8); text(L, title, "F2", 14); line_gap(22)
        for it in items: draw_item(it)
    if answers:
        newpage(); text(L, "Answer Key / Reference Points", "F2", 14); line_gap(24)
        for title, items in sections:
            need(50); line_gap(8); text(L, title, "F2", 14); line_gap(21)
            for it in items:
                rows = [(L if i == 0 else None, f"{it['no']}." if i == 0 else "", 72, ln) for i, ln in enumerate(_wrap(it["answer"] or "(no reference answer stored)", SZ, 520 - 72))]
                need(min(len(rows) * LEAD + 4, 600))
                for xl, label, xt, ln in rows:
                    if y[0] < BOT: newpage()
                    if label: text(xl, label, "F1", SZ)
                    text(xt, ln, "F1", SZ); line_gap(LEAD)
                line_gap(4)
    newpage()
    fonts = _pdf_fonts()
    if fonts: print("PDF font:", fonts["reg"]["name"], "/", fonts["bold"]["name"])
    if fonts:                                                    # embed the Palatino-type font (objects 3-8)
        import zlib
        objs = [b"<< /Type /Catalog /Pages 2 0 R >>", None]; fo = []
        for k, base in (("reg", 5), ("bold", 7)):
            F = fonts[k]
            objs.append((f"<< /Type /Font /Subtype /{'Type1' if F['cff'] else 'TrueType'} /BaseFont /{F['name']} /FirstChar 32 /LastChar 255 /Widths [{' '.join(map(str, F['widths']))}] "
                         f"/FontDescriptor {base} 0 R /Encoding /WinAnsiEncoding >>").encode())
        for k, base in (("reg", 5), ("bold", 7)):
            F = fonts[k]; z = zlib.compress(F["data"])
            objs.append((f"<< /Type /FontDescriptor /FontName /{F['name']} /Flags 34 /FontBBox [{' '.join(map(str, F['bbox']))}] /ItalicAngle 0 "
                         f"/Ascent {F['asc']} /Descent {F['dsc']} /CapHeight {F['cap']} /StemV {120 if k == 'bold' else 80} /FontFile{'3' if F['cff'] else '2'} {base + 1} 0 R >>").encode())
            sub = b"/Subtype /OpenType " if F["cff"] else b"/Length1 %d " % len(F["data"])
            objs.append(b"<< " + sub + b"/Filter /FlateDecode /Length %d >>\nstream\n" % len(z) + z + b"\nendstream")
    else:
        print("⚠ Book Antique / Palatino-type font not found - PDF uses Helvetica. Run the first cell again (it installs fonts-texgyre).")
        objs = [b"<< /Type /Catalog /Pages 2 0 R >>", None,
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"]
    kids = []
    for pg in pages or [[]]:
        stream = "\n".join(pg).encode("cp1252", "replace")
        objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        cid = len(objs)
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {cid} 0 R >>".encode())
        kids.append(f"{len(objs)} 0 R")
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>".encode()
    out, offs = bytearray(b"%PDF-1.6\n"), []
    for i, o in enumerate(objs, 1):
        offs.append(len(out)); out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xr = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for o in offs: out += b"%010d 00000 n \n" % o
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF" % (len(objs) + 1, xr)
    return bytes(out)

print("✅ Faculty features ready")
import os
# ============ CELL 5: WEB APP (Flask serves the dashboard) ============
import functools, threading
from flask import Flask, request, jsonify, Response
from werkzeug.serving import make_server
from werkzeug.exceptions import HTTPException

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 80 * 1024 * 1024

def _token():
    h = request.headers.get("Authorization", "")
    return h[7:] if h.startswith("Bearer ") else ""

@app.errorhandler(Exception)
def _err(e):
    if isinstance(e, HTTPException): return jsonify(error=e.description), e.code
    if isinstance(e, PermissionError): return jsonify(error=str(e)), 401 if "expired" in str(e) else 403
    if isinstance(e, ValueError): return jsonify(error=str(e)), 400
    import traceback; traceback.print_exc()
    return jsonify(error="Server error: " + str(e)), 500

@app.get("/")
def index(): return Response(PAGE, mimetype="text/html")

@app.get("/api/meta")
def api_meta(): return jsonify(levels=BLOOM, has_key=bool(DEFAULT_KEY))

@app.post("/api/register")
def api_register():
    d = request.get_json(force=True); register(d.get("name", ""), d.get("email", ""), d.get("password", ""), "Faculty")
    return jsonify(ok=True)

@app.post("/api/login")
def api_login():
    d = request.get_json(force=True); tok, u = login(d.get("email", ""), d.get("password", ""))
    return jsonify(token=tok, user={"name": u["name"], "role": u["role"], "email": u["email"]})

@app.get("/api/stats")
def api_stats(): return jsonify(faculty_stats(_token()))

@app.get("/api/subjects")
def api_subjects():
    if not verify_token(_token()): raise PermissionError("Session expired. Please log in again.")
    return jsonify(get_subjects())

@app.get("/api/units")
def api_units():
    if not verify_token(_token()): raise PermissionError("Session expired. Please log in again.")
    return jsonify(get_units(request.args.get("subject", "")))

JOBS = {}

def _run_job(uid, fn, *a, **kw):
    """Run a long task (AI generation) in the background so the browser never times out; the page polls /api/job/<id>."""
    jid = secrets.token_hex(8)
    JOBS[jid] = {"uid": uid, "status": "running", "progress": "Starting...", "result": None, "error": None, "t": time.time()}
    def work():
        try:
            JOBS[jid]["result"] = fn(*a, progress=lambda m: JOBS[jid].__setitem__("progress", m), **kw)
            JOBS[jid]["status"] = "done"
        except Exception as e:
            if not isinstance(e, (ValueError, PermissionError)):
                import traceback; traceback.print_exc()
            JOBS[jid]["error"] = str(e) if isinstance(e, (ValueError, PermissionError)) else "Server error: " + str(e)
            JOBS[jid]["status"] = "error"
    threading.Thread(target=work, daemon=True).start()
    for k in [k for k, v in JOBS.items() if time.time() - v["t"] > 3600]: JOBS.pop(k, None)
    return jid

@app.post("/api/generate")
def api_generate():
    tok = _token(); p = require_role(tok, "Faculty")
    f, fm = request.files, request.form
    sy, bk = f.getlist("syllabus"), f.getlist("textbook")
    if not sy: raise ValueError("Please choose a syllabus file.")
    def _n(key, default):
        try: return max(0, min(200, int(fm.get(key, default))))
        except (TypeError, ValueError): raise ValueError("Question counts must be whole numbers (0-200).")
    limits = {"Very Short": _n("vs", 20), "Short": _n("sh", 10), "Long": _n("lg", 5)}
    multi = _n("lm", limits["Long"]) if fm.get("lm", "") != "" else None          # Long questions that have sub-questions (the rest are direct)
    if multi is not None and multi > limits["Long"]: raise ValueError(f"Long questions with sub-questions ({multi}) cannot be more than the total Long questions ({limits['Long']}).")
    jid = _run_job(p["uid"], upload_syllabus_textbook, tok, fm.get("subject", ""), fm.get("title", ""),
                   [(x.filename, x.read()) for x in sy], [(x.filename, x.read()) for x in bk],
                   limits=limits, only_units=parse_unit_filter(fm.get("units", "")), replace=fm.get("replace", "1") == "1",
                   level=fm.get("level", "All Levels"),
                   engine="ai" if fm.get("engine", "ai") == "ai" else "offline", api_key="", extra=fm.get("extra", ""), multi=multi)
    return jsonify(job=jid)

@app.get("/api/job/<jid>")
def api_job(jid):
    p = require_role(_token(), "Faculty")
    j = JOBS.get(jid)
    if not j or j["uid"] != p["uid"]: raise ValueError("Generation job not found (the server may have restarted). Please generate again.")
    return jsonify(status=j["status"], progress=j["progress"], error=j["error"], result=j["result"] if j["status"] == "done" else None)

@app.post("/api/upload")
def api_upload():
    fl = request.files.get("file")
    if not fl: raise ValueError("Choose a file first.")
    return jsonify(upload_question_file(_token(), request.form.get("subject", ""), request.form.get("title", ""),
                                        request.form.get("desc", ""), fl.filename, fl.read()))

@app.get("/api/questions")
def api_list():
    a = request.args
    return jsonify(list_questions(_token(), a.get("subject"), a.get("unit"), a.get("level"), a.get("qtype"), a.get("search")))

@app.post("/api/questions")
def api_add():
    add_question(_token(), **request.get_json(force=True)); return jsonify(ok=True)

@app.put("/api/questions/<int:qid>")
def api_edit(qid):
    edit_question(_token(), qid, **request.get_json(force=True)); return jsonify(ok=True)

@app.delete("/api/questions/<int:qid>")
def api_delete(qid):
    delete_question(_token(), qid); return jsonify(ok=True)

@app.post("/api/download")
def api_download():
    if not verify_token(_token()): raise PermissionError("Session expired. Please log in again.")
    d = request.get_json(force=True)
    qs, meta, fmt, ans = d.get("questions") or [], d.get("meta") or {}, d.get("format", "pdf"), bool(d.get("answers"))
    if not qs: raise ValueError("Nothing to download. Generate a question set first.")
    maker, mime = {"pdf": (make_pdf, "application/pdf"), "docx": (make_docx, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
                   "txt": (make_txt, "text/plain; charset=utf-8"), "print": (make_html, "text/html; charset=utf-8")}.get(fmt, (None, None))
    if not maker: raise ValueError("Unknown format.")
    return Response(maker(qs, meta, ans), mimetype=mime)

_FONT_DIR = "/content" if os.path.isdir("/content") else "."
@app.get("/api/pdffont")
def api_pdffont_get():
    if not verify_token(_token()): raise PermissionError("Session expired. Please log in again.")
    return jsonify(ok=all(os.path.exists(os.path.join(_FONT_DIR, n)) for n in ("bkant.ttf", "antquab.ttf")))

@app.post("/api/pdffont")
def api_pdffont_post():
    """Receives Book Antiqua (regular + bold) read by the browser from the user's own PC, once per Colab session."""
    if not verify_token(_token()): raise PermissionError("Session expired. Please log in again.")
    blobs = []
    for key in ("reg", "bold"):
        fl = request.files.get(key); data = fl.read() if fl else b""
        if len(data) < 20000 or data[:4] not in (b"\x00\x01\x00\x00", b"true"): raise ValueError("That is not a TrueType font file")
        blobs.append(data)
    for name, data in zip(("bkant.ttf", "antquab.ttf"), blobs): open(os.path.join(_FONT_DIR, name), "wb").write(data)
    return jsonify(ok=True)


PAGE = r'''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>QuestionForge – Bloom's Question Bank</title>
<style>
:root{--bg:#f5f6fd;--card:#ffffff;--ink:#141a33;--mute:#59627f;--line:#e3e7f4;--brand:#4f46e5;--brand2:#8b5cf6;--side:#ffffff;--ok:#059669;--bad:#dc2626;--r:18px;
--sh:0 10px 32px rgba(79,70,229,.08),0 2px 6px rgba(20,26,51,.05);color-scheme:light}
*{box-sizing:border-box}html,body{margin:0}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--ink);font-size:15px;min-height:100vh;
background:radial-gradient(900px 500px at 8% -5%,#e4e8ff 0,transparent 60%),radial-gradient(800px 500px at 100% 0,#fde7f3 0,transparent 55%),radial-gradient(900px 600px at 60% 110%,#e0f2fe 0,transparent 60%),#f5f6fd}
button,input,select,textarea{font:inherit;color:var(--ink)}
h1,h2,h3,h4{margin:0;color:var(--ink)}h3{font-size:18px;letter-spacing:-.2px}.mute{color:var(--mute)}.small{font-size:13px}
code{background:#eef0ff;color:#3730a3;padding:2px 7px;border-radius:7px;font-size:12.5px}
/* auth */
.auth{min-height:100vh;display:grid;grid-template-columns:1.1fr 1fr}
.hero{background:linear-gradient(145deg,#e0e7ff,#efe4ff 50%,#ffe3f0);color:var(--ink);padding:52px;display:flex;flex-direction:column;justify-content:center;gap:22px;position:relative;overflow:hidden;border-right:1px solid var(--line)}
.hero:before{content:"";position:absolute;width:340px;height:340px;border-radius:50%;background:rgba(99,102,241,.13);left:-110px;top:-110px}
.hero:after{content:"";position:absolute;width:420px;height:420px;border-radius:50%;background:rgba(236,72,153,.11);right:-130px;bottom:-130px}
.hero>*{position:relative;z-index:1}
.brand{font-size:30px;font-weight:800;letter-spacing:-.5px;background:linear-gradient(90deg,#4338ca,#7c3aed,#db2777);-webkit-background-clip:text;background-clip:text;color:transparent}
.hero h1{color:#1b1f4b}.hero p{max-width:460px;color:#3b4266;line-height:1.6;margin:0;font-size:16px}
.pyr{display:flex;flex-direction:column;align-items:center;gap:7px;margin-top:8px;max-width:430px}
.pyr div{height:36px;border-radius:11px;color:#fff;font-weight:700;font-size:13px;display:flex;align-items:center;justify-content:center;box-shadow:0 6px 14px rgba(30,36,80,.18)}
.authwrap{display:flex;align-items:center;justify-content:center;padding:28px}
.authcard{width:100%;max-width:430px;background:var(--card);border-radius:24px;box-shadow:0 20px 60px rgba(79,70,229,.14),0 3px 8px rgba(20,26,51,.05);padding:34px;border:1px solid var(--line);border-top:5px solid var(--brand)}
.authcard h2{font-size:26px;letter-spacing:-.4px}
.tabs{display:flex;background:#eef0fb;border-radius:13px;padding:4px;margin:20px 0}
.tabs button{flex:1;border:0;background:none;padding:10px;border-radius:10px;cursor:pointer;font-weight:700;color:var(--mute);transition:.15s}
.tabs button.on{background:#fff;color:var(--brand);box-shadow:0 3px 10px rgba(79,70,229,.15)}
/* forms */
label{display:block;font-size:13px;font-weight:700;margin:14px 0 6px;color:#2b3150}
input,select,textarea{width:100%;padding:11px 14px;border:1.5px solid #d9def0;border-radius:12px;background:#fff;color:var(--ink);outline:none;transition:.15s}
input::placeholder,textarea::placeholder{color:#97a0bb}
input:hover,select:hover,textarea:hover{border-color:#b9c0e3}
input:focus,select:focus,textarea:focus{border-color:var(--brand);box-shadow:0 0 0 4px rgba(79,70,229,.13)}
textarea{min-height:84px;resize:vertical}
input[type=checkbox]{accent-color:var(--brand)}
.btn{border:0;cursor:pointer;padding:11px 20px;border-radius:12px;font-weight:700;background:linear-gradient(135deg,var(--brand),var(--brand2));color:#fff;transition:.18s;display:inline-flex;gap:8px;align-items:center;justify-content:center;box-shadow:0 6px 16px rgba(79,70,229,.28)}
.btn:hover{transform:translateY(-2px);box-shadow:0 10px 22px rgba(79,70,229,.36)}.btn:disabled{opacity:.55;cursor:not-allowed;transform:none;box-shadow:none}
.btn.ghost{background:#fff;color:var(--ink);border:1.5px solid #d9def0;box-shadow:0 2px 6px rgba(20,26,51,.05)}.btn.ghost:hover{border-color:var(--brand);color:var(--brand);box-shadow:0 6px 14px rgba(79,70,229,.14)}
.btn.ghost .spin{border-color:rgba(79,70,229,.25);border-top-color:var(--brand)}
.btn.red{background:linear-gradient(135deg,#ef4444,#dc2626)}.btn.full{width:100%;margin-top:20px;padding:13px}.btn.sm{padding:6px 11px;font-size:13px}
.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px}
/* shell */
.shell{display:grid;grid-template-columns:268px 1fr;min-height:100vh}
.side{background:#fff;color:var(--ink);padding:22px 14px;display:flex;flex-direction:column;gap:6px;position:sticky;top:0;height:100vh;border-right:1px solid var(--line);box-shadow:6px 0 28px rgba(79,70,229,.05)}
.side .brand{font-size:23px;padding:4px 10px 20px}
.nav{display:flex;align-items:center;gap:12px;padding:12px 14px;border-radius:13px;cursor:pointer;border:0;background:none;color:#394062;text-align:left;font-weight:600;width:100%;transition:.15s}
.nav span{font-size:18px;width:26px;text-align:center}
.nav:hover{background:#eef0ff;color:var(--brand)}
.nav.on{background:linear-gradient(135deg,var(--brand),var(--brand2));color:#fff;box-shadow:0 8px 18px rgba(79,70,229,.32)}
.me{margin-top:auto;background:linear-gradient(135deg,#eef0ff,#fdf0fa);border:1px solid var(--line);border-radius:16px;padding:12px;display:flex;gap:10px;align-items:center}
.me .small{color:var(--mute)}
.av{width:40px;height:40px;border-radius:50%;background:linear-gradient(135deg,#f472b6,#818cf8);display:grid;place-items:center;color:#fff;font-weight:800;flex:none;box-shadow:0 4px 10px rgba(129,140,248,.4)}
.main{padding:28px 32px;min-width:0}
.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;gap:12px}
.top h2{font-size:27px;letter-spacing:-.5px;font-weight:800}.burger{display:none}
.card{background:var(--card);border-radius:var(--r);box-shadow:var(--sh);padding:24px;border:1px solid var(--line)}
.grid{display:grid;gap:18px}.g4{grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}
.stat{display:flex;gap:15px;align-items:center;border-top:4px solid var(--brand);transition:.18s}
.stat:hover{transform:translateY(-3px);box-shadow:0 16px 36px rgba(79,70,229,.14)}
.stat .ic{width:54px;height:54px;border-radius:16px;display:grid;place-items:center;font-size:25px;background:#eef0ff}
.stat b{font-size:30px;display:block;line-height:1;color:var(--ink)}.stat span{color:var(--mute);font-size:13px;font-weight:600}
.g4>.stat:nth-child(1){border-top-color:#6366f1}.g4>.stat:nth-child(1) .ic{background:#eef0ff}
.g4>.stat:nth-child(2){border-top-color:#10b981}.g4>.stat:nth-child(2) .ic{background:#dcfce7}
.g4>.stat:nth-child(3){border-top-color:#f59e0b}.g4>.stat:nth-child(3) .ic{background:#fef3c7}
.g4>.stat:nth-child(4){border-top-color:#ec4899}.g4>.stat:nth-child(4) .ic{background:#fce7f3}
.bar{display:flex;align-items:center;gap:12px;margin:12px 0}.bar .n{width:130px;font-weight:700;font-size:13px;color:#2b3150}.bar .t{flex:1;height:13px;background:#eef0fb;border-radius:9px;overflow:hidden}
.bar .t i{display:block;height:100%;border-radius:9px;background:linear-gradient(90deg,var(--c),color-mix(in srgb,var(--c) 60%,#fff));transition:width .7s}.bar .v{width:40px;text-align:right;font-weight:800;font-size:13px}
.badge{display:inline-block;padding:4px 11px;border-radius:20px;font-size:12px;font-weight:700;color:color-mix(in srgb,var(--c) 80%,#000);background:color-mix(in srgb,var(--c) 15%,#fff);border:1px solid color-mix(in srgb,var(--c) 30%,#fff);white-space:nowrap}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:#3a4266;padding:12px 10px;background:#f1f3fd;border-bottom:1.5px solid var(--line);font-weight:800}
th:first-child{border-radius:10px 0 0 10px}th:last-child{border-radius:0 10px 10px 0}
td{padding:13px 10px;border-bottom:1px solid var(--line);vertical-align:top;color:var(--ink)}tr:hover td{background:#f7f8ff}
.tw{overflow-x:auto}.chips{display:flex;flex-wrap:wrap;gap:7px}.chip{padding:5px 12px;border-radius:20px;font-size:12.5px;font-weight:700;background:color-mix(in srgb,var(--c) 12%,#fff);color:color-mix(in srgb,var(--c) 85%,#000);border:1px solid color-mix(in srgb,var(--c) 25%,#fff)}
.drop{border:2px dashed #c5cbea;border-radius:16px;padding:22px;text-align:center;cursor:pointer;transition:.18s;position:relative;background:linear-gradient(180deg,#fafbff,#f3f4ff)}
.drop:hover,.drop.on{border-color:var(--brand);background:#eef0ff;transform:translateY(-2px)}.drop input{position:absolute;inset:0;opacity:0;cursor:pointer}
.drop b{display:block;margin-top:6px;color:var(--ink)}
.bl{border-left:6px solid var(--c);transition:.18s}.bl:hover{transform:translateY(-3px);box-shadow:0 16px 36px rgba(30,36,80,.12)}
.sheet h3{font-size:20px}.q{padding:14px 0;border-bottom:1px dashed var(--line)}.q .meta{display:flex;gap:8px;align-items:center;margin-bottom:6px;flex-wrap:wrap}
.q .opt{margin:3px 0 0 22px;color:var(--ink)}.ans{margin-top:8px;padding:10px 12px;background:#f3f4ff;border-radius:10px;font-size:13.5px;color:var(--mute)}
.warn{background:#fff4d6;color:#7a4a05;padding:12px 15px;border-radius:12px;font-weight:600;border:1px solid #fde4a1}
.toast{position:fixed;right:20px;bottom:20px;display:flex;flex-direction:column;gap:10px;z-index:99}
.toast div{padding:12px 18px;border-radius:13px;color:#fff;font-weight:600;box-shadow:0 10px 26px rgba(20,26,51,.22);animation:in .25s;max-width:360px}
.toast .ok{background:linear-gradient(135deg,#10b981,#059669)}.toast .bad{background:linear-gradient(135deg,#ef4444,#dc2626)}@keyframes in{from{transform:translateY(14px);opacity:0}}
.modal{position:fixed;inset:0;background:rgba(30,36,80,.35);display:grid;place-items:center;z-index:50;padding:16px}
.modal .card{width:100%;max-width:640px;max-height:92vh;overflow:auto;box-shadow:0 30px 80px rgba(30,36,80,.28)}
.spin{width:18px;height:18px;border:3px solid rgba(255,255,255,.45);border-top-color:#fff;border-radius:50%;animation:s .7s linear infinite}@keyframes s{to{transform:rotate(360deg)}}
.hello{background:linear-gradient(120deg,#e0e7ff,#f0e5ff 55%,#ffe4f1);color:var(--ink);border:1px solid #d9d9f7;position:relative;overflow:hidden}
.hello:after{content:"";position:absolute;width:240px;height:240px;border-radius:50%;background:rgba(99,102,241,.12);right:-60px;top:-90px}
.hello h2{color:#1b1f4b;font-size:26px}.hello p{color:#3b4266;margin:8px 0 0;font-size:15.5px}.hello>*{position:relative;z-index:1}
@media(max-width:900px){.auth{grid-template-columns:1fr}.hero{padding:30px}.shell{grid-template-columns:1fr}
.side{position:fixed;left:-290px;width:268px;z-index:40;transition:.25s}.side.open{left:0}.burger{display:inline-flex}.main{padding:18px 14px}.g2{grid-template-columns:1fr}}
.thsw{display:none}.themepos{display:none}
.uchip{border:1.5px solid var(--line);background:#fff;border-radius:12px;padding:9px 14px;cursor:pointer;font-weight:700;display:inline-flex;gap:8px;align-items:center;transition:.15s}
.uchip small{background:#eef0fb;border-radius:20px;padding:1px 8px;color:var(--mute);font-weight:700}.uchip.on{background:linear-gradient(135deg,var(--brand),var(--brand2));color:#fff;border-color:transparent}
.uchip.on small{background:rgba(255,255,255,.25);color:#fff}.uchip.zero{opacity:.55}.dlbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:18px;padding:16px;background:linear-gradient(120deg,#f3f4ff,#fdf2f9);border-radius:14px;border:1px solid var(--line)}
::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:#cdd2ee;border-radius:10px}::-webkit-scrollbar-thumb:hover{background:#aab1de}
@media print{body{background:#fff}body *{visibility:hidden}#sheet,#sheet *{visibility:visible}#sheet{position:absolute;left:0;top:0;width:100%;box-shadow:none;border:0}.noprint{display:none!important}}
</style></head>
<body><div id="app"></div><div class="toast" id="toast"></div>
<script>
const $=(s,r=document)=>r.querySelector(s),$$=(s,r=document)=>[...r.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const themeSwitch=()=>'';
function setTheme(t){t='light';document.documentElement.dataset.theme=t;try{localStorage.setItem('qf-theme',t)}catch(e){}$$('.thsw button').forEach(b=>b.classList.toggle('on',b.dataset.th===t))}
document.documentElement.dataset.theme='light';
document.addEventListener('click',e=>{const b=e.target.closest('[data-th]');if(b)setTheme(b.dataset.th)});
let S={token:null,user:null,meta:null,view:'overview'};
try{const o=JSON.parse(sessionStorage.getItem('qf')||'null');if(o){S.token=o.token;S.user=o.user}}catch(e){}
async function api(path,{method='GET',body,form}={}){
  const o={method,headers:{}};if(S.token)o.headers.Authorization='Bearer '+S.token;
  if(form)o.body=form;else if(body){o.headers['Content-Type']='application/json';o.body=JSON.stringify(body)}
  const ac=new AbortController(),tm=setTimeout(()=>ac.abort(),form?180000:25000);o.signal=ac.signal;
  let r;try{r=await fetch(path,o)}catch(e){throw new Error(e.name==='AbortError'?'The server is not responding. Re-run the last Colab cell, open the NEW link it prints, and try again.':'Cannot reach the server. Re-run the last Colab cell and open the new link.')}finally{clearTimeout(tm)}
  let d={};try{d=await r.json()}catch(e){}
  if(r.status===401&&S.token){logout()}
  if(!r.ok)throw new Error(d.error||'Something went wrong');return d}
function toast(m,ok=true){const d=document.createElement('div');d.className=ok?'ok':'bad';d.textContent=m;$('#toast').append(d);setTimeout(()=>d.remove(),4200)}
const L=n=>S.meta.levels.find(x=>x.name===n)||{color:'#64748b',name:n};
const badge=n=>`<span class="badge" style="--c:${L(n).color}">${esc(n)}</span>`;
const busy=(b,on,txt)=>{if(on){b.dataset.t=b.innerHTML;b.disabled=true;b.innerHTML='<span class="spin"></span> '+(txt||'Working…')}else{b.disabled=false;b.innerHTML=b.dataset.t}};
function bars(map,total){const mx=Math.max(1,...Object.values(map));return S.meta.levels.map(l=>`<div class="bar"><div class="n">${l.icon} ${l.name}</div><div class="t"><i style="--c:${l.color};width:${(map[l.name]||0)/mx*100}%"></i></div><div class="v">${map[l.name]||0}</div></div>`).join('')}
function donut(map){const e=Object.entries(map),t=e.reduce((a,b)=>a+b[1],0)||1,cols=['#6366f1','#10b981','#f59e0b','#ec4899'];let a=0,segs='';
  e.forEach(([k,v],i)=>{const p=v/t*100;segs+=`<circle r="15.9" cx="21" cy="21" fill="none" stroke="${cols[i%4]}" stroke-width="6" stroke-dasharray="${p} ${100-p}" stroke-dashoffset="${25-a}"/>`;a+=p});
  return `<div style="display:flex;gap:22px;align-items:center;flex-wrap:wrap"><svg viewBox="0 0 42 42" width="150" height="150"><circle r="15.9" cx="21" cy="21" fill="none" stroke="var(--bg)" stroke-width="6"/>${segs}<text x="21" y="23" text-anchor="middle" font-size="7" font-weight="800" fill="currentColor">${t===1&&!e.length?0:t}</text></svg><div>${e.map(([k,v],i)=>`<div style="margin:6px 0"><span style="display:inline-block;width:11px;height:11px;border-radius:3px;background:${cols[i%4]};margin-right:8px"></span><b>${k}</b> <span class="mute">${v}</span></div>`).join('')||'<span class="mute">No data yet</span>'}</div></div>`}
/* ---------- auth ---------- */
function renderAuth(){
  const pyr=[...S.meta.levels].reverse().map((l,i)=>`<div style="background:${l.color};width:${46+i*10}%">${l.icon} ${l.name}</div>`).join('');
  $('#app').innerHTML=`<div class="auth"><div class="themepos">${themeSwitch()}</div><section class="hero"><div class="brand">🎓 QuestionForge</div><h1 style="font-size:34px;line-height:1.15">Question Bank Generator, organised by how deeply you think.</h1><p>Faculty upload a syllabus and textbook. QuestionForge builds a question bank mapped to Bloom's six cognitive levels. Then generate and download question sets by unit, format and Bloom level.</p><div class="pyr">${pyr}</div></section>
  <section class="authwrap"><div class="authcard"><h2>Welcome 👋</h2><span class="mute small">Sign in or create an account to continue</span>
  <div class="tabs"><button class="on" data-t="l">Login</button><button data-t="r">Register</button></div>
  <form id="fl"><label>Email</label><input id="le" type="email" required><label>Password</label><input id="lp" type="password" required><button class="btn full">Login</button></form>
  <form id="fr" hidden><label>Full name</label><input id="rn" required><label>Email</label><input id="re" type="email" required><label>Password (min 6)</label><input id="rp" type="password" minlength="6" required>
  <button class="btn full">Create faculty account</button></form></div></section></div>`;
  setTheme(document.documentElement.dataset.theme);$$('.tabs button').forEach(b=>b.onclick=()=>{$$('.tabs button').forEach(x=>x.classList.toggle('on',x===b));$('#fl').hidden=b.dataset.t!=='l';$('#fr').hidden=b.dataset.t!=='r'});
  $('#fl').onsubmit=async e=>{e.preventDefault();const b=$('button.btn',e.target);busy(b,1,'Signing in');try{const d=await api('/api/login',{method:'POST',body:{email:$('#le').value,password:$('#lp').value}});S.token=d.token;S.user=d.user;try{sessionStorage.setItem('qf',JSON.stringify({token:d.token,user:d.user}))}catch(x){}S.view='overview';renderShell()}catch(x){toast(x.message,0);busy(b,0)}};
  $('#fr').onsubmit=async e=>{e.preventDefault();const b=$('button.btn',e.target);busy(b,1,'Creating');try{await api('/api/register',{method:'POST',body:{name:$('#rn').value,email:$('#re').value,password:$('#rp').value,role:'Faculty'}});toast('Account created – please log in');$$('.tabs button')[0].click();$('#le').value=$('#re').value}catch(x){toast(x.message,0)}busy(b,0)}}
function logout(){S.token=S.user=null;try{sessionStorage.removeItem('qf')}catch(e){}renderAuth()}
/* ---------- shell ---------- */
const NAV={Faculty:[['overview','🏠','Dashboard'],['generate','✨','Generate from Syllabus'],['upload','📤','Upload Question File'],['add','➕','Add Question'],['bank','🗂️','Question Bank'],['bloom','🧠',"Bloom's Taxonomy"]]};
const TITLES={overview:'Dashboard',generate:'Generate from Syllabus & Textbook',upload:'Upload Question File',add:'Add a Question',bank:'Question Bank',bloom:"Bloom's Taxonomy"};
function renderShell(){const u=S.user,nav=NAV[u.role];
  $('#app').innerHTML=`<div class="shell"><aside class="side" id="side"><div class="brand">🎓 QuestionForge</div>${nav.map(n=>`<button class="nav" data-v="${n[0]}"><span>${n[1]}</span>${n[2]}</button>`).join('')}
  <div class="me"><div class="av">${esc(u.name[0].toUpperCase())}</div><div style="min-width:0;flex:1"><b style="color:var(--ink);display:block;overflow:hidden;text-overflow:ellipsis">${esc(u.name)}</b><span class="small">${u.role}</span></div><button class="btn ghost sm" id="lo" title="Logout">⎋</button></div></aside>
  <main class="main"><div class="top"><div style="display:flex;gap:12px;align-items:center"><button class="btn ghost sm burger" id="bg">☰</button><h2 id="ttl"></h2></div><span class="noprint">${themeSwitch()}</span></div><div id="view"></div></main></div>`;
  setTheme(document.documentElement.dataset.theme);$$('.nav').forEach(b=>b.onclick=()=>{go(b.dataset.v);$('#side').classList.remove('open')});$('#lo').onclick=logout;$('#bg').onclick=()=>$('#side').classList.toggle('open');go(S.view)}
async function go(v){S.view=v;$$('.nav').forEach(b=>b.classList.toggle('on',b.dataset.v===v));$('#ttl').textContent=TITLES[v];$('#view').innerHTML='<div class="mute">Loading…</div>';
  try{await VIEWS[v]()}catch(e){$('#view').innerHTML=`<div class="warn">${esc(e.message)}</div><button class="btn" style="margin-top:14px" onclick="go('${v}')">↻ Retry</button>`}}
/* ---------- shared: question form ---------- */
function qForm(q,subs){q=q||{};return `<form id="qf"><label>Question *</label><textarea id="fq" required>${esc(q.question||'')}</textarea>
<div class="row"><div><label>Subject *</label><input id="fs" list="sl" required value="${esc(q.subject||'')}"><datalist id="sl">${(subs||[]).map(s=>`<option>${esc(s)}</option>`).join('')}</datalist></div>
<div><label>Unit *</label><input id="fu" required placeholder="Unit 1" value="${esc(q.unit||'')}"></div><div><label>Topic</label><input id="ft" value="${esc(q.topic||'')}"></div></div>
<div class="row"><div><label>Bloom level *</label><select id="fl2">${S.meta.levels.map(l=>`<option ${q.bloom_level===l.name?'selected':''}>${l.name}</option>`).join('')}</select></div>
<div><label>Format *</label><select id="fy">${['Very Short','Short','Long'].map(t=>`<option ${q.question_type===t?'selected':''}>${t}</option>`).join('')}</select></div>
<div><label>Marks (set by format)</label><input id="fm" type="number" value="${q.marks||1}" readonly></div></div>
<div id="hint" class="small mute" style="margin-top:8px"></div>
<label>Parts a), b), c)… for Long questions <span class="small">(one per line, optional)</span></label><textarea id="fp">${esc((q.parts||[]).join('\n'))}</textarea><label>Options (optional, separate with | )</label><input id="fo" value="${esc((q.options||[]).join(' | '))}"><label>Answer / reference points</label><textarea id="fa">${esc(q.answer||'')}</textarea></form>`}
function hintInit(){const f=()=>{const l=L($('#fl2').value);$('#hint').innerHTML=`💡 <b>${l.name}</b> questions often start with: ${(l.verbs||[]).slice(0,12).join(', ')}…`};$('#fl2').onchange=f;f();const m=()=>{$('#fm').value={'Very Short':1,'Short':2,'Long':10}[$('#fy').value]};$('#fy').onchange=m;m()}
const qData=()=>({question:$('#fq').value,subject:$('#fs').value.trim(),unit:$('#fu').value.trim(),topic:$('#ft').value.trim(),bloom_level:$('#fl2').value,question_type:$('#fy').value,marks:+$('#fm').value,options:$('#fo').value,parts:$('#fp').value,answer:$('#fa').value});
function dropzone(id,label,accept,multi){return `<div class="drop" id="${id}"><input type="file" accept="${accept}" ${multi?'multiple':''}><div style="font-size:30px">📄</div><b>${label}</b><span class="small mute" id="${id}n">${multi?'Drag files here or click to browse – you can add several':'Drag a file here or click to browse'}</span></div>`}
function dzInit(id){const d=$('#'+id),i=$('input',d),n=$('#'+id+'n'),multi=i.multiple,idle=n.textContent;let keep=[];
 const show=()=>{if(!multi){n.textContent=i.files[0]?i.files[0].name:idle;return}
  const dt=new DataTransfer();keep.forEach(f=>dt.items.add(f));i.files=dt.files;
  n.innerHTML=keep.length?keep.map(f=>'📎 '+esc(f.name)).join('<br>')+'<br><a href="#" class="dzc" style="position:relative;z-index:2;color:var(--brand)">✕ Clear all</a> · click to add more':idle;
  const c=$('.dzc',n);if(c)c.onclick=ev=>{ev.preventDefault();ev.stopPropagation();keep=[];show()}};
 i.onchange=()=>{if(multi)[...i.files].forEach(f=>{if(!keep.some(k=>k.name===f.name&&k.size===f.size))keep.push(f)});show()};
 ['dragenter','dragover'].forEach(e=>d.addEventListener(e,()=>d.classList.add('on')));['dragleave','drop'].forEach(e=>d.addEventListener(e,()=>d.classList.remove('on')))}
function fileNameFor(qs,meta,fmt,answers){
  const clean=t=>String(t||'').replace(/[^A-Za-z0-9]+/g,'_').replace(/^_+|_+$/g,'');
  const uniq=a=>[...new Set(a.filter(Boolean))];
  const nums=uniq(qs.map(q=>q.unit)).map(u=>(String(u).match(/\d+/)||[null])[0]);
  let unit;
  if(nums.length&&nums.every(n=>n!==null)){const n=nums.map(Number).sort((a,b)=>a-b);
    unit=n.length===1?'Unit_'+n[0]:(n[n.length-1]-n[0]===n.length-1?'Units_'+n[0]+'-'+n[n.length-1]:'Units_'+n.join('_'))}
  else unit=clean(uniq(qs.map(q=>q.unit)).join('_'))||'All_Units';
  const fm=uniq(qs.map(q=>q.question_type)),lv=uniq(qs.map(q=>q.bloom_level));
  const fmt1=fm.length===1?clean(fm[0]):'All_Formats',lv1=lv.length===1?clean(lv[0]):'All_Levels';
  const d=new Date(),date=d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');
  return [clean(meta.subject)||'Questions',unit,fmt1,lv1,qs.length+'Q',answers?'with_answers':'',date].filter(Boolean).join('_')+'.'+fmt}
/* Book Antiqua for the PDF: Chrome/Edge can read the font from this PC (one 'Allow' click); it is sent to the server once per session */
async function ensureAntiqua(){if(S.fontOk!==undefined)return S.fontOk;
 try{const h=await(await fetch('/api/pdffont',{headers:{Authorization:'Bearer '+S.token}})).json();if(h.ok)return S.fontOk=true}catch(x){}
 if(!window.queryLocalFonts)return S.fontOk=false;
 try{const all=await window.queryLocalFonts(),pick=st=>all.find(f=>f.family==='Book Antiqua'&&f.style===st);const rg=pick('Regular'),bd=pick('Bold');if(!rg||!bd)return S.fontOk=false;
  const fd=new FormData();fd.append('reg',await rg.blob(),'bkant.ttf');fd.append('bold',await bd.blob(),'antquab.ttf');
  const r=await fetch('/api/pdffont',{method:'POST',headers:{Authorization:'Bearer '+S.token},body:fd});return S.fontOk=r.ok}catch(x){return S.fontOk=false}}
async function downloadSet(fmt,btn,questions,meta,answers){busy(btn,1,'Preparing');
  if(fmt==='pdf'&&!(await ensureAntiqua()))toast('Book Antiqua not available here, so the PDF uses a look-alike font. Use Chrome or Edge and click Allow when asked.',0);
  try{const r=await fetch('/api/download',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+S.token},body:JSON.stringify({format:fmt,questions,meta,answers:!!answers})});
   if(!r.ok){let e={};try{e=await r.json()}catch(x){}throw new Error(e.error||'Download failed')}
   const bl=await r.blob(),a=document.createElement('a');a.href=URL.createObjectURL(bl);a.download=fileNameFor(questions,meta,fmt,answers);document.body.append(a);a.click();a.remove();toast('Downloaded '+fmt.toUpperCase())}catch(x){toast(x.message,0)}busy(btn,0)}
/* dd/mm/yyyy hh:mm in the viewer's own (system) time zone; server stores UTC */
const p2=n=>String(n).padStart(2,'0');
function fmtDT(s){if(!s)return '';let t=String(s);if(!/[TZ]/.test(t))t=t.replace(' ','T')+'Z';const d=new Date(t);if(isNaN(d))return esc(s);return `${p2(d.getDate())}/${p2(d.getMonth()+1)}/${d.getFullYear()} ${p2(d.getHours())}:${p2(d.getMinutes())}`}
const fmtD=d=>`${p2(d.getDate())}/${p2(d.getMonth()+1)}/${d.getFullYear()}`;
const VIEWS={};
/* ---------- faculty views ---------- */
VIEWS.overview=async()=>{
 if(S.user.role==='Faculty'){const s=await api('/api/stats');
  $('#view').innerHTML=`<div class="card hello" style="margin-bottom:18px"><h2>Hello, ${esc(S.user.name.split(' ')[0])} 👋</h2><p>Turn Your Syllabus into Smart Questions!</p><div style="margin-top:14px"><button class="btn ghost" onclick="go('generate')">✨ Generate questions</button></div></div>
  <div class="grid g4"><div class="card stat"><div class="ic">❓</div><div><b>${s.total}</b><span>Total questions</span></div></div><div class="card stat"><div class="ic">📚</div><div><b>${s.subjects}</b><span>Subjects</span></div></div><div class="card stat"><div class="ic">🧱</div><div><b>${s.units}</b><span>Units covered</span></div></div><div class="card stat"><div class="ic">🗃️</div><div><b>${s.recent.length}</b><span>Recent banks</span></div></div></div>
  <div class="grid g2" style="margin-top:18px"><div class="card"><h3>Bloom's level distribution</h3><div style="margin-top:8px">${bars(s.by_level)}</div></div><div class="card"><h3>Question types</h3><div style="margin-top:16px">${donut(s.by_type)}</div></div></div>
  <div class="card" style="margin-top:18px"><h3>Recent uploads</h3><div class="tw"><table><tr><th>Title</th><th>Subject</th><th>Questions</th><th>Files</th><th>Date</th></tr>${s.recent.map(b=>`<tr><td><b>${esc(b.title)}</b></td><td>${esc(b.subject)}</td><td>${b.n}</td><td class="small mute">${esc(b.file)}</td><td class="small">${fmtDT(b.upload_date)}</td></tr>`).join('')||'<tr><td colspan="5" class="mute">Nothing uploaded yet.</td></tr>'}</table></div></div>`}
};
async function runGen(fd,btn){const j=await api('/api/generate',{method:'POST',form:fd});
 for(;;){await new Promise(r=>setTimeout(r,1500));const s=await api('/api/job/'+j.job);
  if(s.status==='error')throw new Error(s.error||'Generation failed');
  if(s.status==='done')return s.result;
  btn.innerHTML='<span class="spin"></span> '+esc(s.progress||'Working…')}}
VIEWS.generate=async()=>{const subs=[];
 $('#view').innerHTML=`<div class="grid g2"><div class="card"><h3>1 · Upload files</h3></span>
 <form id="gf"><div class="row"><div><label>Subject *</label><input id="gs" list="sl" required placeholder="e.g. DBMS"><datalist id="sl">${subs.map(s=>`<option>${esc(s)}</option>`).join('')}</datalist></div><div><label>Bank title</label><input id="gt" placeholder="optional"></div></div>
 <div class="row" style="margin-top:14px">${dropzone('d1','Syllabus file(s)','.pdf,.docx,.txt',1)}${dropzone('d2','Textbook(s) (optional)','.pdf,.docx,.txt',1)}</div><div style="margin-top:18px;padding-top:6px;border-top:1.5px solid var(--line)"><label style="color:var(--ink)">How many questions to generate <span class="small mute">(per unit, for each format; 0 = skip that format)</span></label>
 <div class="row"><div><label>Very Short (1 mark)</label><input id="gvs" type="number" min="0" max="200" value="20"></div><div><label>Short (2 marks)</label><input id="gsh" type="number" min="0" max="200" value="10"></div><div><label>Long (10 marks)</label><input id="glg" type="number" min="0" max="200" value="5"></div><div><label>…Long <u>with sub-questions</u></label><input id="glm" type="number" min="0" max="200" value="2"></div></div>
 <div class="small mute" id="glh" style="margin:2px 0 6px"></div>
 <div class="row"><div><label>Bloom level</label><select id="gbl"><option value="All Levels">All levels (count shared across levels)</option><option value="Each Level">Each level separately (count × 6 levels)</option>${S.meta.levels.map(l=>`<option value="${l.name}">${l.name} only</option>`).join('')}</select></div></div>
 <div class="row"><div><label>Generation engine</label><select id="gen"><option value="ai">✨ AI – accurate, exam-style questions (recommended)</option><option value="offline">Offline templates (no API key, basic quality)</option></select></div><div><label>AI API key</label><div class="small" style="padding:12px 0;font-weight:700;color:var(--ok)">🔒 Loaded securely from the server configuration</div></div></div>

 <div class="row"><div><label>Only these units <span class="small">(optional, e.g. 1,3 or 1-3)</span></label><input id="gun" placeholder="blank = all units"></div></div>
 <label style="display:flex;gap:8px;align-items:center;font-weight:600"><input type="checkbox" id="grp" checked style="width:auto"> Replace my earlier auto-generated questions for this subject</label></div>
 <button class="btn full">✨ Generate Bloom-mapped questions</button></form></div>
 <div class="card" id="gr"><h3>2 · Result</h3><p class="mute">Results appear here after generation.</p></div></div>`;
 dzInit('d1');dzInit('d2');
 const fixM=()=>{const L=Math.max(0,+$('#glg').value||0),m=$('#glm');m.max=L;if((+m.value||0)>L)m.value=L;const M=Math.max(0,+m.value||0);
  $('#glh').innerHTML=`Long questions per unit: <b>${L-M} direct</b> (single question) + <b>${M} with sub-questions</b> (a, b, c…). Written by the AI engine.`};
 $('#glg').oninput=fixM;$('#glm').oninput=fixM;fixM();
 api('/api/subjects').then(l=>{const dl=$('#sl');if(dl)dl.innerHTML=l.map(x=>`<option>${esc(x)}</option>`).join('')}).catch(()=>{});
 $('#gf').onsubmit=async e=>{e.preventDefault();const f1=[...$('#d1 input').files],f2=[...$('#d2 input').files];if(!f1.length)return toast('Choose at least one syllabus file',0);
  const fd=new FormData();fd.append('subject',$('#gs').value);fd.append('title',$('#gt').value);f1.forEach(f=>fd.append('syllabus',f));fd.append('vs',$('#gvs').value||0);fd.append('sh',$('#gsh').value||0);fd.append('lg',$('#glg').value||0);fd.append('lm',$('#glm').value||0);fd.append('units',$('#gun').value);fd.append('level',$('#gbl').value);fd.append('replace',$('#grp').checked?'1':'0');f2.forEach(f=>fd.append('textbook',f));fd.append('engine',$('#gen').value);
  const b=$('button.btn',e.target);busy(b,1,'Generating…');
  try{const r=await runGen(fd,b);toast(r.added+' questions saved');S.gen={questions:r.questions||[],meta:{subject:$('#gs').value.trim(),units:$('#gun').value.trim()||'All Units',qtype:[['Very Short','gvs'],['Short','gsh'],['Long','glg']].filter(x=>+$('#'+x[1]).value>0).map(x=>x[0]).join(' + '),level:({'All Levels':'All Levels','Each Level':'Each Level'}[$('#gbl').value]||$('#gbl').value)}};
   $('#gr').innerHTML=`<h3>✅ ${r.added} new questions saved</h3>${r.engine==='ai'?`<div class="small mute">✨ Written by AI${r.syllabus_only?' from the syllabus topics':' from the syllabus and textbook text'}. Review them in the Question Bank before using them.</div>`:`<div class="small mute">Used ${r.n_syllabus} syllabus file(s) and ${r.n_books} textbook(s)${r.syllabus_only?' – syllabus only, no textbook text':''}.</div>`}${(r.skipped_files||[]).length?`<div class="warn" style="margin:12px 0">Not enough readable text, so these were skipped (scanned PDF?):<br>${r.skipped_files.map(esc).join('<br>')}</div>`:''}${r.removed?`<div class="small mute">Replaced ${r.removed} earlier auto-generated question(s).</div>`:''}${(r.shortfalls||[]).length?`<div class="warn" style="margin:12px 0">Fewer questions than requested for:<br>${r.shortfalls.map(esc).join('<br>')}<br><span class="small">Add more topics to the syllabus or upload the textbook to get more.</span></div>`:''}<div style="margin:12px 0">${bars(r.by_level)}</div><div class="chips" style="margin-bottom:12px">${Object.entries(r.by_type).map(([t,n])=>`<span class="chip" style="--c:#4f46e5">${t}: ${n}${t==='Long'&&r.with_parts!=null?` (${r.with_parts} with sub-questions, ${n-r.with_parts} direct)`:''}</span>`).join('')}</div><h4>Units & topics found</h4>${Object.entries(r.units).map(([u,t])=>`<div style="margin:8px 0"><b>${esc(u)}</b><div class="chips" style="margin-top:4px">${t.slice(0,8).map(x=>`<span class="chip" style="--c:#4f46e5">${esc(x)}</span>`).join('')}</div></div>`).join('')}<button class="btn ghost" style="margin-top:12px" onclick="go('bank')">Open question bank →</button>${(r.questions||[]).length?`<div class="dlbar noprint"><b>⬇ Download these ${r.questions.length} questions</b><label style="margin:0;display:flex;gap:6px;align-items:center;font-size:13px"><input type="checkbox" id="gak" style="width:auto"> Include answers</label><button class="btn" data-f="pdf">PDF</button><button class="btn" data-f="docx">Word (.docx)</button><button class="btn ghost" data-f="txt">Text (.txt)</button></div>`:''}`;
   $$('#gr .dlbar [data-f]').forEach(x=>x.onclick=()=>downloadSet(x.dataset.f,x,S.gen.questions,S.gen.meta,$('#gak').checked))}
  catch(x){toast(x.message,0)}busy(b,0)}};
VIEWS.upload=async()=>{
 $('#view').innerHTML=`<div class="card" style="max-width:720px"><h3>Upload a ready-made question bank</h3><p class="small mute">CSV or JSON with columns: <code>question, subject, unit, topic, bloom_level, question_type, options, answer</code>. <b>question_type</b> = Very Short (1 mark), Short (2 marks) or Long (10 marks); marks are set automatically. Separate options with <code>|</code>. Bloom level must be one of: ${S.meta.levels.map(l=>l.name).join(', ')}.</p>
 <button class="btn ghost sm" id="tp">⬇ Download CSV template</button><form id="uf"><div class="row"><div><label>Subject (if not in file)</label><input id="us"></div><div><label>Title</label><input id="ut"></div></div><label>Description</label><input id="ud">
 <div style="margin-top:14px">${dropzone('d3','Question file','.csv,.json')}</div><button class="btn full">📤 Upload</button></form><div id="ur"></div></div>`;dzInit('d3');
 $('#tp').onclick=()=>{const t='question,subject,unit,topic,bloom_level,question_type,marks,options,answer\n"What is a primary key?",DBMS,Unit 2,Keys,Remembering,Very Short,1,,"A column that uniquely identifies a row"\n';const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([t],{type:'text/csv'}));a.download='question_template.csv';a.click()};
 $('#uf').onsubmit=async e=>{e.preventDefault();const f=$('#d3 input').files[0];if(!f)return toast('Choose a file',0);const fd=new FormData();fd.append('subject',$('#us').value);fd.append('title',$('#ut').value);fd.append('desc',$('#ud').value);fd.append('file',f);
  const b=$('button.btn.full');busy(b,1,'Uploading');try{const r=await api('/api/upload',{method:'POST',form:fd});toast(r.added+' questions added');$('#ur').innerHTML=`<p><b>${r.added}</b> added.</p>${r.errors.length?`<div class="warn">Skipped:<br>${r.errors.slice(0,10).map(esc).join('<br>')}</div>`:''}`}catch(x){toast(x.message,0)}busy(b,0)}};
VIEWS.add=async()=>{const subs=await api('/api/subjects');
 $('#view').innerHTML=`<div class="card" style="max-width:820px">${qForm(null,subs)}<button class="btn full" id="sv">➕ Add question</button></div>`;hintInit();
 $('#sv').onclick=async()=>{if(!$('#qf').reportValidity())return;const b=$('#sv');busy(b,1,'Saving');try{await api('/api/questions',{method:'POST',body:qData()});toast('Question added');$('#fq').value='';$('#fa').value='';$('#fo').value=''}catch(x){toast(x.message,0)}busy(b,0)}};
VIEWS.bank=async()=>{const subs=await api('/api/subjects');let rows=[];
 $('#view').innerHTML=`<div class="card"><div class="row"><div><label>Subject</label><select id="bs"><option>All</option>${subs.map(s=>`<option>${esc(s)}</option>`).join('')}</select></div><div><label>Unit</label><select id="bu"><option>All</option></select></div>
 <div><label>Bloom level</label><select id="bl"><option>All</option>${S.meta.levels.map(l=>`<option>${l.name}</option>`).join('')}</select></div><div><label>Format</label><select id="bt"><option>All</option><option>Very Short</option><option>Short</option><option>Long</option></select></div><div><label>Search</label><input id="bq" placeholder="keyword…"></div></div>
 <div class="small mute" id="bc" style="margin:14px 0 4px"></div><div class="tw"><table><thead><tr><th>#</th><th>Question</th><th>Level</th><th>Format</th><th>Marks</th><th>Unit</th><th></th></tr></thead><tbody id="bb"></tbody></table></div>
 <div class="dlbar noprint"><b>⬇ Download the <span id="bdn">0</span> question(s) matching the filters above</b><label style="margin:0;display:flex;gap:6px;align-items:center;font-size:13px"><input type="checkbox" id="bak" style="width:auto"> Include answers</label><button class="btn" data-f="pdf">PDF</button><button class="btn" data-f="docx">Word (.docx)</button><button class="btn ghost" data-f="txt">Text (.txt)</button></div></div>`;
 const load=async()=>{const p=new URLSearchParams({subject:$('#bs').value,unit:$('#bu').value,level:$('#bl').value,qtype:$('#bt').value,search:$('#bq').value});rows=await api('/api/questions?'+p);
  $('#bc').textContent=`${rows.length} question(s)`+(rows.length>300?' – showing first 300 (downloads include all '+rows.length+')':'');$('#bdn').textContent=rows.length;
  $('#bb').innerHTML=rows.slice(0,300).map(r=>`<tr><td class="mute">${r.id}</td><td style="max-width:420px;white-space:pre-wrap">${esc(r.question)}${(r.parts||[]).length?`<div class="small" style="margin-top:6px">${r.parts.map((p,i)=>'abcdefgh'[i%8]+') '+esc(p)).join('<br>')}</div>`:''}${r.options.length?`<div class="small mute">${r.options.map(esc).join(' · ')}</div>`:''}</td><td>${badge(r.bloom_level)}</td><td>${r.question_type}</td><td>${r.marks}</td><td class="small">${esc(r.unit)}<div class="mute">${esc(r.topic||'')}</div></td><td style="white-space:nowrap"><button class="btn ghost sm" data-e="${r.id}">✏️</button> <button class="btn ghost sm" data-d="${r.id}">🗑️</button></td></tr>`).join('')||'<tr><td colspan="7" class="mute">No questions match.</td></tr>'};
 $('#bs').onchange=async()=>{const us=$('#bs').value==='All'?[]:await api('/api/units?subject='+encodeURIComponent($('#bs').value));$('#bu').innerHTML='<option>All</option>'+us.map(u=>`<option>${esc(u)}</option>`).join('');load()};
 ['bu','bl','bt'].forEach(i=>$('#'+i).onchange=load);let tm;$('#bq').oninput=()=>{clearTimeout(tm);tm=setTimeout(load,300)};
 $('#bb').onclick=async e=>{const be=e.target.closest('[data-e]'),bd=e.target.closest('[data-d]');
  if(bd){if(!confirm('Delete this question?'))return;try{await api('/api/questions/'+bd.dataset.d,{method:'DELETE'});toast('Deleted');load()}catch(x){toast(x.message,0)}}
  if(be){const q=rows.find(r=>r.id==be.dataset.e),m=document.createElement('div');m.className='modal';m.innerHTML=`<div class="card"><h3>Edit question #${q.id}</h3>${qForm(q,subs)}<div style="display:flex;gap:10px;margin-top:18px"><button class="btn" id="ms">💾 Save</button><button class="btn ghost" id="mc">Cancel</button></div></div>`;document.body.append(m);hintInit();
   $('#mc',m).onclick=()=>m.remove();$('#ms',m).onclick=async()=>{try{await api('/api/questions/'+q.id,{method:'PUT',body:qData()});toast('Updated');m.remove();load()}catch(x){toast(x.message,0)}}}};
 $$('#view .dlbar [data-f]').forEach(b=>b.onclick=()=>{if(!rows.length)return toast('No questions to download',0);const v=i=>$('#'+i).value;downloadSet(b.dataset.f,b,rows,{subject:v('bs')==='All'?'All Subjects':v('bs'),units:v('bu')==='All'?'All Units':v('bu'),qtype:v('bt')==='All'?'All Formats':v('bt'),level:v('bl')==='All'?'All Levels':v('bl')},$('#bak').checked)});
 load()};
VIEWS.bloom=async()=>{
 $('#view').innerHTML=`<p class="mute" style="margin-top:-8px">Revised Bloom's Taxonomy action verbs. Questions in this app are tagged with one of six cognitive levels.</p><div class="grid g2">${S.meta.levels.map((l,i)=>`<div class="card bl" style="--c:${l.color}"><div style="display:flex;gap:10px;align-items:center"><span style="font-size:26px">${l.icon}</span><h3 style="color:${l.color}">${i+1}. ${l.name}</h3></div><p class="small mute">${esc(l.definition)}</p><div class="chips">${l.verbs.map(v=>`<span class="chip" style="--c:${l.color}">${esc(v)}</span>`).join('')}</div></div>`).join('')}</div><p class="small mute">Source: Anderson, L. W., &amp; Krathwohl, D. R. (2001). <i>A taxonomy for learning, teaching, and assessing</i>, Abridged Edition. Boston, MA: Allyn and Bacon.</p>`};
(async()=>{try{S.meta=await api('/api/meta')}catch(e){document.body.innerHTML='Server error';return}S.token&&S.user&&S.user.role==='Faculty'?renderShell():renderAuth()})();
</script></body></html>
'''

# ---------- start the server ----------
try: _server.shutdown(); _server.server_close()          # re-running the cell restarts cleanly and frees the port
except Exception: pass
_server = None
for PORT in range(5055, 5070):
    try: _server = make_server("0.0.0.0", PORT, app, threaded=True); break
    except OSError: continue
if _server is None: raise RuntimeError("No free port between 5055 and 5069. Use Runtime > Restart session, then run the cells again.")
threading.Thread(target=_server.serve_forever, daemon=True).start()
print("✅ QuestionForge is running")
print("🔒 Server-side AI key is configured" if DEFAULT_KEY else "ℹ️ No server-side AI key configured — set the LLM_KEY environment secret")
try:
    from google.colab import output
    output.serve_kernel_port_as_window(PORT, anchor_text="👉 Click here to open QuestionForge in a new tab")
except ImportError:
    print(f"Open http://127.0.0.1:{PORT} in your browser")