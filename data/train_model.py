"""
Обучает модель LightGBM на data/dataset.csv.
Убирает признаки-«утечки», которые не связаны с вредоносностью.
Сохраняет модель в model/lgbm_model.txt.
"""
import os
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix,
)

DATA_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(DATA_DIR, "dataset.csv")
MODEL_PATH = os.path.join(DATA_DIR, "..", "model", "lgbm_model.txt")

# Признаки-«утечки»: сильно различаются между malware и чистыми файлами,
# но не потому что malware — а потому что malware собран другим компилятором.
# Их надо исключить, чтобы модель училась на поведенческих признаках.
LEAKY_FEATURES = [
    "file_size",
    "checksum",
    "image_base",
    "size_of_code",
    "size_of_image",
    "size_of_headers",
    "timestamp",
]


def main():
    print("[*] Загружаю датасет...")
    df = pd.read_csv(CSV_PATH)

    print(f"    Строк:    {len(df)}")
    print(f"    Malware:  {sum(df['label'] == 1)}")
    print(f"    Clean:    {sum(df['label'] == 0)}")

    # Убираем label и признаки-утечки
    X = df.drop(columns=["label"] + LEAKY_FEATURES)
    y = df["label"]

    print(f"\n[*] Используемые признаки ({len(X.columns)}):")
    for col in X.columns:
        print(f"    - {col}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\n[*] Обучаю LightGBM...")
    print(f"    Train: {len(X_train)}")
    print(f"    Test:  {len(X_test)}")

    model = lgb.LGBMClassifier(
        n_estimators=300,
        learning_rate=0.05,
        num_leaves=31,
        max_depth=-1,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print(f"\n[+] Метрики качества:")
    print(f"    Accuracy:  {acc:.4f}")
    print(f"    Precision: {prec:.4f}")
    print(f"    Recall:    {rec:.4f}")
    print(f"    F1:        {f1:.4f}")

    print(f"\n[*] Confusion matrix (TN FP / FN TP):")
    print(confusion_matrix(y_test, y_pred))

    print(f"\n[*] Топ-10 важных признаков:")
    importances = sorted(
        zip(X.columns, model.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )
    for name, imp in importances[:10]:
        print(f"    {name}: {imp}")

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    model.booster_.save_model(MODEL_PATH)
    print(f"\n[+] Модель сохранена: {MODEL_PATH}")


if __name__ == "__main__":
    main()