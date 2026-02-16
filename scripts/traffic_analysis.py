import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

print("Loading datasets...")
ddos = pd.read_csv("data/ddos.csv")
portscan = pd.read_csv("data/portscan.csv")

df = pd.concat([ddos, portscan], ignore_index=True)
print("Datasets merged successfully")
print("Total records:", len(df))

print("Cleaning data...")
df.columns = df.columns.str.strip()
df.replace([float("inf"), -float("inf")], pd.NA, inplace=True)
df.dropna(inplace=True)
numeric_cols = ["Flow Packets/s","Flow Bytes/s","SYN Flag Count","Destination Port"]
for col in numeric_cols:
    df[col] = pd.to_numeric(df[col], errors="coerce")
df.dropna(inplace=True)
print("Remaining records:", len(df))

os.makedirs("outputs", exist_ok=True)
sns.set_style("whitegrid")

print("Creating traffic label chart...")
label_counts = df["Label"].value_counts()
plt.figure(figsize=(6,6))
colors = sns.color_palette("pastel")
plt.pie(label_counts, labels=label_counts.index, autopct="%1.1f%%", colors=colors, startangle=90)
plt.title("Traffic Distribution")
plt.savefig("outputs/traffic_labels.png")
plt.close()

print("Creating port analysis chart...")
top_ports_chart = df["Destination Port"].value_counts().head(10)
plt.figure(figsize=(10,6))
sns.barplot(x=top_ports_chart.index, y=top_ports_chart.values)
plt.title("Top Targeted Ports")
plt.xlabel("Port")
plt.ylabel("Number of Flows")
plt.tight_layout()
plt.savefig("outputs/top_ports.png")
plt.close()

print("Creating packet rate chart...")
plt.figure(figsize=(10,6))
sns.histplot(df["Flow Packets/s"], bins=50, kde=True)
plt.title("Packet Rate Distribution")
plt.tight_layout()
plt.savefig("outputs/packet_rate.png")
plt.close()

print("Calculating risk scores...")
df["Risk Score"] = (
    0.4 * (df["SYN Flag Count"] / df["SYN Flag Count"].max()) +
    0.3 * (df["Flow Packets/s"] / df["Flow Packets/s"].max()) +
    0.3 * (df["Flow Bytes/s"] / df["Flow Bytes/s"].max())
)
risk_threshold = df["Risk Score"].quantile(0.98)
high_risk = df[df["Risk Score"] > risk_threshold]
high_risk.to_csv("outputs/high_risk_flows.csv", index=False)

print("Classifying attack types...")
syn_thresh = df["SYN Flag Count"].quantile(0.99)
pkt_thresh = df["Flow Packets/s"].quantile(0.99)
top_ports = df["Destination Port"].value_counts().head(20).index
df["Attack Type"] = "Benign"
df.loc[df["SYN Flag Count"] > syn_thresh, "Attack Type"] = "SYN Flood"
df.loc[df["Flow Packets/s"] > pkt_thresh, "Attack Type"] = "UDP/Traffic Flood"
df.loc[
    (df["Attack Type"] == "Benign") &
    (df["Destination Port"].isin(top_ports)),
    "Attack Type"
] = "Port Scan"
df.to_csv("outputs/all_flows_with_attack_type.csv", index=False)

print("Creating attack distribution chart...")
plt.figure(figsize=(8,6))
sns.countplot(data=df, x="Attack Type", order=df["Attack Type"].value_counts().index)
plt.title("Detected Attack Types")
plt.tight_layout()
plt.savefig("outputs/attack_types.png")
plt.close()

print("Creating targeted port analysis...")
top_ports_attack = (
    df[df["Attack Type"] != "Benign"]
    .groupby(["Destination Port","Attack Type"])
    .size()
    .reset_index(name="Count")
)
top_ports_attack = top_ports_attack.sort_values("Count", ascending=False).head(15)
plt.figure(figsize=(12,6))
sns.barplot(data=top_ports_attack, x="Destination Port", y="Count", hue="Attack Type")
plt.title("Most Targeted Ports by Attack Type")
plt.tight_layout()
plt.savefig("outputs/attacked_ports_by_type.png")
plt.close()

print("Creating traffic spike chart...")
df["Time"] = pd.date_range(start="2025-01-01", periods=len(df), freq="s")
traffic_over_time = df.resample("1Min", on="Time")["Flow Bytes/s"].sum()
plt.figure(figsize=(12,6))
traffic_over_time.plot()
plt.title("Traffic Volume Over Time")
plt.ylabel("Bytes per Minute")
plt.tight_layout()
plt.savefig("outputs/traffic_spikes.png")
plt.close()

print("Creating heatmap...")
heatmap_data = df.pivot_table(
    values="Flow Packets/s",
    index="Destination Port",
    columns="Attack Type",
    aggfunc="mean"
).head(20)
plt.figure(figsize=(12,8))
sns.heatmap(heatmap_data, cmap="Reds")
plt.title("Port vs Attack Type Heatmap")
plt.tight_layout()
plt.savefig("outputs/heatmap.png")
plt.close()

print("\nALERT SUMMARY:\n")
print("High Risk Flows:", len(high_risk))
print("\nAttack Type Counts:")
print(df["Attack Type"].value_counts())

print("\nAnalysis Complete.")
print("Check the outputs folder for charts and reports.")
