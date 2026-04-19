import pandas as pd

df = pd.read_csv("dataset/attack_data.csv")

# Select needed columns
df = df[[
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Flow Packets/s",
    "Flow Bytes/s",
    "Label"
]]

# Rename to match your system
df.columns = [
    "duration",
    "packet_count",
    "byte_count",
    "packet_rate",
    "byte_rate",
    "label"
]

# Clean
df.replace([float("inf"), -float("inf")], 0, inplace=True)
df.fillna(0, inplace=True)

# Convert duration to seconds (important!)
df["duration"] = df["duration"] / 1e6

print(df.head())

# Save aligned dataset
df.to_csv("dataResults/flow_dataset.csv", index=False)

print("✅ Flow dataset created")