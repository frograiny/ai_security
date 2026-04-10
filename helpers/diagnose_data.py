import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle, os, sys

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
tf.get_logger().setLevel('ERROR')

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")
MAX_LEN = 150

model = tf.keras.models.load_model(os.path.join(MODEL_DIR, "deep_learning_agent_core.keras"))
with open(os.path.join(MODEL_DIR, 'tokenizer.pkl'), 'rb') as f:
    tokenizer = pickle.load(f)
with open(os.path.join(MODEL_DIR, 'label_encoder.pkl'), 'rb') as f:
    le = pickle.load(f)

out = open(r"d:\AI\ai_security\diagnosis_result.txt", "w", encoding="utf-8")

def P(s=""):
    print(s)
    out.write(s + "\n")

P(f"Labels: {list(le.classes_)}")
P(f"MAX_LEN = {MAX_LEN}")

test_payloads = [
    ("admin' OR 1", "SQLi"),
    ("' OR 1=1--", "SQLi"),
    ("' OR '1'='1", "SQLi"),
    ("admin' OR '1'='1'--", "SQLi"),
    ("1' UNION SELECT null,null--", "SQLi"),
    ("<img src=x onerror=alert(1)>", "XSS"),
    ("https://www.google.com/search?q=cat", "Normal"),
    ("http://localhost:8080/api/users", "Normal"),
    ("Xin chao toi muon tim tai lieu", "Normal"),
]

P("")
P("=" * 90)
for payload, expected in test_payloads:
    seq = tokenizer.texts_to_sequences([payload])
    pad = pad_sequences(seq, maxlen=MAX_LEN, padding='post', truncating='post')
    pred = model.predict(pad, verbose=0)[0]

    top_idx = np.argsort(pred)[::-1]
    result_label = le.inverse_transform([top_idx[0]])[0]
    result_conf = pred[top_idx[0]] * 100
    ok = "OK" if result_label == expected else "WRONG"
    fill = len(seq[0]) / MAX_LEN * 100

    P(f"Payload: {payload}")
    P(f"  Expected: {expected} | Got: {result_label} ({result_conf:.1f}%) [{ok}]")
    P(f"  Length: {len(payload)} chars | Tokens: {len(seq[0])}/{MAX_LEN} ({fill:.0f}% used)")

    # All class probabilities
    probs = []
    for j in top_idx:
        l = le.inverse_transform([j])[0]
        p = pred[j] * 100
        if p > 0.1:
            probs.append(f"{l}={p:.1f}%")
    P(f"  All probs: {' | '.join(probs)}")
    P("-" * 90)

# Token analysis for admin' OR 1
P("")
P("=" * 90)
P("TOKEN ANALYSIS: admin' OR 1")
P("=" * 90)
payload = "admin' OR 1"
seq = tokenizer.texts_to_sequences([payload])[0]
P(f"Char-by-char tokens:")
for ch in payload:
    t = tokenizer.texts_to_sequences([ch])
    tid = t[0][0] if t[0] else "OOV"
    P(f"  '{ch}' -> token {tid}")

# Check if short SQLi patterns exist in training somehow
P("")
P("=" * 90)
P("SHORT vs LONG SQLi COMPARISON")
P("=" * 90)
sqli_short = ["admin' OR 1", "' OR 1=1--", "' OR '1'='1", "admin'--"]
sqli_long = [
    "1' UNION SELECT username,password FROM users--",
    "1'; DROP TABLE users--",
    "' UNION SELECT null,table_name FROM information_schema.tables--",
]

for group_name, group in [("SHORT (<15 chars)", sqli_short), ("LONG (>30 chars)", sqli_long)]:
    P(f"\n{group_name}:")
    for p in group:
        seq = tokenizer.texts_to_sequences([p])
        pad = pad_sequences(seq, maxlen=MAX_LEN, padding='post', truncating='post')
        pred = model.predict(pad, verbose=0)[0]
        idx = np.argmax(pred)
        label = le.inverse_transform([idx])[0]
        conf = pred[idx] * 100
        ok = "OK" if label == "SQLi" else "!!"
        P(f"  [{ok}] {label:>10} {conf:>5.1f}% | {p}")

out.close()
print("\nDone! Results in diagnosis_result.txt")
