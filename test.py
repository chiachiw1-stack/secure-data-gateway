import requests
import random
import time

url = "http://localhost:8080/api/v1/submit_sprint"

agents = [
    {"agent_id": "001", "agent_name": "王小明"},
    {"agent_id": "002", "agent_name": "陳小美"},
    {"agent_id": "003", "agent_name": "李大華"},
    {"agent_id": "004", "agent_name": "吳麗萍"},
    {"agent_id": "005", "agent_name": "頁書華"},
]

pii_samples = ["", "", "", "wang@gmail.com", "0912345678", "A123456789", "", "", "","", ""]

# loop 隨機生成資料
while True:
    agent = random.choice(agents)
    data = {
        "agent_id": agent["agent_id"],
        "agent_name": agent["agent_name"],
        "module_id": random.choice(["OB", "CS", "HR"]),
        "accuracy": random.randint(60, 100),
        "interaction_speed": random.randint(200, 500),
        "personal_information": random.choice(pii_samples),
    }
    res = requests.post(url, json=data)
    print(res.json())
    time.sleep(5)