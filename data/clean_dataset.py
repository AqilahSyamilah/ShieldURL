import pandas as pd

# read dataset
df = pd.read_csv("data/PhishingData.csv")

# show actual column names
print("Columns in dataset:")
print(df.columns)

# basic cleaning
df = df.drop_duplicates()
df = df.dropna()

# save cleaned version
df.to_csv("data/cleaned_dataset.csv", index=False)


print("Cleaned dataset saved as data/cleaned_dataset.csv")