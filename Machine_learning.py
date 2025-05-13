import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report  
import xgboost as xgb
import pickle


train_df = pd.read_csv(r'D:\Major Project\Dataset\UNSW_NB15_training-set.csv', low_memory=False)
test_df = pd.read_csv(r'D:\Major Project\Dataset\UNSW_NB15_testing-set.csv', low_memory=False)


combined_df = pd.concat([train_df, test_df], ignore_index=True)


combined_df.drop(columns=['id'], inplace=True, errors='ignore')


combined_df.fillna(0, inplace=True)

combined_df['binary_label'] = combined_df['attack_cat'].apply(
    lambda x: 1 if x in ['DoS', 'Generic'] else 0
)

for col in combined_df.select_dtypes(include='object').columns:
    if col != 'attack_cat':
        le = LabelEncoder()
        combined_df[col] = le.fit_transform(combined_df[col])

train_data = combined_df.iloc[:len(train_df)]
test_data = combined_df.iloc[len(train_df):]

X_train = train_data.drop(columns=['attack_cat', 'binary_label'])
y_train = train_data['binary_label']
X_test = test_data.drop(columns=['attack_cat', 'binary_label'])
y_test = test_data['binary_label']

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

clf = xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss')
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred, target_names=['Normal/Other', 'DoS/Generic']))


with open("ddos_model.pkl", "wb") as f:
    pickle.dump(clf, f)
