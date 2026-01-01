print("Training script started...")

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
import joblib
import os

def main():
    # Define paths relative to this script
    current_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(current_dir, '..', 'data', 'phishing.csv')
    model_path = os.path.join(current_dir, '..', 'model', 'url_phishing_model.pkl')

    print(f"Loading dataset from: {csv_path}")
    if not os.path.exists(csv_path):
        print("Error: Dataset not found!")
        return

    df = pd.read_csv(csv_path)
    
    print("Columns found:", list(df.columns))

    # Label column
    y = df["class"]

    # Feature columns (drop non-features)
    X = df.drop(columns=["class", "Index"], errors="ignore")

    print("Training model...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = LogisticRegression(max_iter=2000)
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"Accuracy: {acc:.4f}")

    joblib.dump(model, model_path)
    print(f"Model saved to: {model_path}")

if __name__ == "__main__":
    main()
