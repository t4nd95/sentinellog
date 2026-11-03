"""Synthetic examples, deliberately not real production data."""

def sample_ssh():
    lines = []
    for i, user in enumerate(["demo", "demo", "demo", "demo", "demo",
                              "user2", "user3", "user4", "user5"]):
        lines.append(
            f"2026-11-03T12:00:{i:02d}+00:00 demo-linux sshd[1234]: "
            f"Failed password for {user} from 192.0.2.10 port 50000 ssh2"
        )
    lines.append(
        "2026-11-03T12:00:15+00:00 demo-linux sshd[1234]: "
        "Accepted password for demo from 192.0.2.10 port 50000 ssh2"
    )
    return "\n".join(lines)
