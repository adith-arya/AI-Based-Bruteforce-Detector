
import csv
import os
import time
import random
from datetime import datetime
from collections import defaultdict
from sklearn.ensemble import RandomForestClassifier

# --------------------------------
# 1. TRAIN THE AI MODEL
# --------------------------------

def train_model():

    random.seed(42)

    data = []
    labels = []

    # Generate sample login behaviour
    for _ in range(2000):

        total = random.randint(1, 20)
        failed = random.randint(0, total)
        users = random.randint(1, min(total, 10))
        rate = total
        ratio = failed / total

        # Generate training labels
        if ((failed >= 6 and total >= 7 and ratio >= 0.75)
            or (failed >= 5 and users >= 4
                and total >= 6 and ratio >= 0.70)):
            label = 1
        else:
            label = 0

        data.append([total, failed, users, rate, ratio])
        labels.append(label)

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    model.fit(data, labels)

    return model


# --------------------------------
# 2. LOGIN DATABASE (CSV)
# --------------------------------

FILE = "login_history.csv"

if not os.path.exists(FILE):
    with open(FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Time", "Username", "IP",
            "Status", "Threat"
        ])


# Store login attempts in memory
attempts = defaultdict(list)
blocked_ips = set()


# --------------------------------
# 3. EXTRACT LOGIN FEATURES
# --------------------------------

def extract_features(ip):

    current = time.time()

    # Consider attempts in the last 60 seconds
    recent = [
        x for x in attempts[ip]
        if current - x["time"] <= 60
    ]

    total = len(recent)

    failed = sum(
        1 for x in recent if not x["success"]
    )

    users = len(set(
        x["username"] for x in recent
    ))

    rate = total

    ratio = failed / total if total else 0

    return [total, failed, users, rate, ratio]


# --------------------------------
# 4. RECORD AND DETECT ATTACKS
# --------------------------------

def record_login(model, username, ip, success):

    if ip in blocked_ips:
        print("\n[BLOCKED] Login attempts from this IP are blocked.")
        return

    event = {
        "time": time.time(),
        "username": username,
        "success": success
    }

    attempts[ip].append(event)

    features = extract_features(ip)

    prediction = 0
    confidence = 0

    # Wait for sufficient login activity
    if features[0] >= 3:
        prediction = model.predict([features])[0]
        confidence = max(model.predict_proba([features])[0])

    if prediction == 1:
        threat = "BRUTE FORCE"
    else:
        threat = "NORMAL"

    status = "SUCCESS" if success else "FAILED"

    # Save login information
    with open(FILE, "a", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            username,
            ip,
            status,
            threat
        ])

    print("\n--------------------------------")
    print("LOGIN ACTIVITY")
    print("--------------------------------")

    print("Username:", username)
    print("IP Address:", ip)
    print("Login Status:", status)
    print("Total Attempts:", features[0])
    print("Failed Attempts:", features[1])

    if prediction == 1:

        print("\n[ALERT] BRUTE FORCE ATTACK DETECTED!")
        print("AI Confidence:", round(confidence * 100, 2), "%")

        blocked_ips.add(ip)

        print("Security Action: IP blocked in simulation")

    else:
        print("\n[SAFE] Normal login activity")

    print("--------------------------------")


# --------------------------------
# 5. NORMAL ACTIVITY SIMULATION
# --------------------------------

def normal_demo(model):

    print("\n--- NORMAL LOGIN SIMULATION ---")

    ip = "192.168.1.10"

    record_login(model, "admin", ip, True)
    record_login(model, "student", ip, False)
    record_login(model, "student", ip, True)


# --------------------------------
# 6. BRUTE FORCE SIMULATION
# --------------------------------

def attack_demo(model):

    print("\n--- BRUTE FORCE SIMULATION ---")

    ip = "192.168.1.99"

    for i in range(8):

        record_login(
            model,
            "admin",
            ip,
            False
        )

        time.sleep(0.15)


# --------------------------------
# 7. MANUAL LOGIN SIMULATION
# --------------------------------

def manual_demo(model):

    print("\n--- MANUAL LOGIN SIMULATION ---")

    username = input("Enter username: ")
    ip = input("Enter IP address: ")

    choice = input("Login successful? (y/n): ")

    success = choice.lower() == "y"

    record_login(model, username, ip, success)


# --------------------------------
# 8. DISPLAY LOGIN HISTORY
# --------------------------------

def view_history():

    print("\n--- LOGIN HISTORY ---")

    with open(FILE, "r") as f:

        reader = csv.reader(f)

        for row in reader:
            print(" | ".join(row))


# --------------------------------
# 9. MAIN PROGRAM
# --------------------------------

def main():

    print("================================")
    print(" AI BRUTE FORCE ATTACK DETECTOR")
    print("================================")

    print("Training AI model...")

    model = train_model()

    print("AI Model Ready!")

    while True:

        print("\n1. Normal Login Simulation")
        print("2. Brute Force Simulation")
        print("3. Manual Login Simulation")
        print("4. View Login History")
        print("5. Exit")

        choice = input("\nEnter your choice: ")

        if choice == "1":
            normal_demo(model)

        elif choice == "2":
            attack_demo(model)

        elif choice == "3":
            manual_demo(model)

        elif choice == "4":
            view_history()

        elif choice == "5":
            print("\nSystem Closed.")
            break

        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()
