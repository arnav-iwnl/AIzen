import random
from datetime import datetime, timedelta

NUM_LOGS = 3000
OUTPUT = "synthetic_error.log"

ERROR_STATES = [6, 7, 8, 9, 10]
SCOREBOARD_SLOTS = list(range(6, 13))

EVENTS = [
    ("worker_init", 0.35),
    ("jk_child", 0.35),
    ("mod_jk_error", 0.25),
    ("directory_forbidden", 0.05),
]

base_time = datetime(2005, 12, 4, 4, 47, 44)


def weighted_choice():
    r = random.random()
    cumulative = 0

    for event, prob in EVENTS:
        cumulative += prob
        if r <= cumulative:
            return event

    return EVENTS[-1][0]


def make_timestamp(dt):
    return dt.strftime("%a %b %d %H:%M:%S %Y")


def worker_init(ts):
    return (
        f"[{ts}] [notice] "
        f"workerEnv.init() ok "
        f"/etc/httpd/conf/workers2.properties"
    )


def jk_child(ts):
    pid = random.randint(1000, 33000)
    slot = random.choice(SCOREBOARD_SLOTS)

    return (
        f"[{ts}] [notice] "
        f"jk2_init() Found child "
        f"{pid} in scoreboard slot {slot}"
    )


def mod_jk_error(ts):
    state = random.choice(ERROR_STATES)

    return (
        f"[{ts}] [error] "
        f"mod_jk child workerEnv "
        f"in error state {state}"
    )


def directory_forbidden(ts):
    ip = ".".join(str(random.randint(1, 255)) for _ in range(4))

    return (
        f"[{ts}] [error] "
        f"[client {ip}] "
        f"Directory index forbidden by rule: "
        f"/var/www/html/"
    )


def generate():
    current = base_time

    with open(OUTPUT, "w") as f:
        for _ in range(NUM_LOGS):
            current += timedelta(
                seconds=random.randint(1, 30)
            )

            ts = make_timestamp(current)
            event = weighted_choice()

            if event == "worker_init":
                line = worker_init(ts)

            elif event == "jk_child":
                line = jk_child(ts)

            elif event == "mod_jk_error":
                line = mod_jk_error(ts)

            else:
                line = directory_forbidden(ts)

            f.write(line + "\n")


if __name__ == "__main__":
    generate()