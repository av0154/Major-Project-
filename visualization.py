import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder

# Step 1: Load Dataset from Local Disk
# Replace with your dataset path
file_path = r"D:\Major Project\Dataset\UNSW_NB15_testing-set.csv" # Ensure the file is in your working directory
df = pd.read_csv(file_path)

# Ensure the dataset has the correct columns
if 'label' not in df.columns:
    raise ValueError("Column 'label' not found in dataset. Please check your CSV.")

# Manually select relevant features based on the dataset columns
selected_features = ['dur', 'sbytes', 'dbytes', 'spkts', 'dpkts', 'smean', 'dmean', 'attack_cat']

# Check if the selected columns exist in the dataset
missing_columns = [col for col in selected_features if col not in df.columns]
if missing_columns:
    raise ValueError(f"Missing columns in dataset: {', '.join(missing_columns)}")

# Encode non-numeric columns (such as 'attack_cat') using LabelEncoder
le = LabelEncoder()

# Apply label encoding to categorical columns
df['attack_cat'] = le.fit_transform(df['attack_cat'])

# Select the subset of features
features_subset = df[selected_features + ['label']]  # Add 'label' for correlation with DoS/DDoS

# Encode 'label' column (if necessary)
df['label'] = le.fit_transform(df['label'])

# Compute the correlation matrix
corr_matrix = features_subset.corr()

# Plot the heatmap with only the selected features
plt.figure(figsize=(10, 7))
sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', fmt='.2f', cbar=True, linewidths=0.5)

# Add a title and labels
plt.title('Correlation Heatmap of Selected Features with DoS/DDoS Label')
plt.tight_layout()

output_file = 'correlation_matrix.png'
plt.savefig(output_file)

# Show the plot
plt.show()

