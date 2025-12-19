import pandas as pd
import os
import joblib
from sklearn.ensemble import IsolationForest

csv_file = "C:\\Users\\Cyber_User\\Desktop\\magshimim\\aegiscore-av\\MainProcces\\notepad.csv"
file_path = "isolation_forest_model.pkl"

if os.path.exists(file_path):
    model = joblib.load("isolation_forest_model.pkl")
else:
    data = pd.read_csv(csv_file)
# ====== Isolation Forest ======
    model = IsolationForest(
        n_estimators=100,   # מספר העצים
        max_samples='auto',
        contamination='auto', # אחוז חריגות מוערך (5%)
        random_state=42
    )
    #train the model
    model.fit(data)
    joblib.dump(model, "isolation_forest_model.pkl")







