import os
import json
import logging
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle

# ===== LOGGING =====
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [RETRAIN] - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ===== CONFIGURATION =====
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "deep_learning_agent_core.keras")
TOKENIZER_PATH = os.path.join(BASE_DIR, "model", "tokenizer.pkl")
LABEL_ENCODER_PATH = os.path.join(BASE_DIR, "model", "label_encoder.pkl")
FP_DATA_PATH = os.path.join(BASE_DIR, "data", "fp_reports.json")

MAX_LEN = 150
LEARNING_RATE = 1e-5
EPOCHS = 3
BATCH_SIZE = 8

def main():
    if not os.path.exists(FP_DATA_PATH):
        logger.info(f"Không tìm thấy file FP data tại: {FP_DATA_PATH}. Không có dữ liệu để học.")
        return

    with open(FP_DATA_PATH, 'r', encoding='utf-8') as f:
        try:
            fp_entries = json.load(f)
        except json.JSONDecodeError:
            logger.error("File json FP bị lỗi, không thể parse.")
            return
            
    if not fp_entries:
        logger.info("Không có dữ liệu False Positive mới để train.")
        return

    # Chuẩn bị dữ liệu
    payloads = [entry['payload'] for entry in fp_entries]
    
    # Ở đây do là False Positive (chặn nhầm), nhãn mong muốn sẽ là "Normal"
    # Lấy LabelEncoder để xác định ID của nhãn "Normal"
    if not os.path.exists(LABEL_ENCODER_PATH):
        logger.error(f"Không tìm thấy LabelEncoder tại: {LABEL_ENCODER_PATH}")
        return
        
    with open(LABEL_ENCODER_PATH, 'rb') as f:
        le = pickle.load(f)
        
    if "Normal" not in le.classes_:
        logger.error("LabelEncoder không có lớp 'Normal'.")
        return
        
    normal_label_idx = int(le.transform(["Normal"])[0])
    
    # Tokenize
    if not os.path.exists(TOKENIZER_PATH):
        logger.error(f"Không tìm thấy Tokenizer tại: {TOKENIZER_PATH}")
        return
        
    with open(TOKENIZER_PATH, 'rb') as f:
        tokenizer = pickle.load(f)
        
    seqs = tokenizer.texts_to_sequences(payloads)
    X = pad_sequences(seqs, maxlen=MAX_LEN, padding='post', truncating='post')
    
    # Label array
    import numpy as np
    y = np.full((len(payloads),), normal_label_idx)
    
    # Load mô hình
    if not os.path.exists(MODEL_PATH):
        logger.error(f"Không tìm thấy Model tại: {MODEL_PATH}")
        return
        
    logger.info(f"Đang load model: {MODEL_PATH}")
    model = tf.keras.models.load_model(MODEL_PATH)
    
    # Đặt learning rate cực nhỏ để tránh Catastrophic Forgetting
    tf.keras.backend.set_value(model.optimizer.learning_rate, LEARNING_RATE)
    
    logger.info(f"Bắt đầu huấn luyện Online Learning trên {len(payloads)} mẫu Normal (FP) mới...")
    model.fit(
        X, y,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        verbose=1
    )
    
    # Lưu lại model
    model.save(MODEL_PATH)
    logger.info(f"✅ Đã cập nhật và lưu mô hình thành công.")
    
    # Backup file FP (để không train lại lần sau)
    import shutil
    from datetime import datetime
    backup_path = FP_DATA_PATH.replace('.json', f'_processed_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
    shutil.move(FP_DATA_PATH, backup_path)
    logger.info(f"Đã dọn dẹp file FP và backup sang {backup_path}")

if __name__ == "__main__":
    main()
