import json
from datetime import datetime
from pathlib import Path

def print_report(results):
    print("\n")
    print("=" *70)
    print("CONFIGURATION COMPLIANCE REPORT")
    print("=" *70)

    current_device = None

    for result in results:
        if result.device != current_device:
            current_device = result.device

            print()
            print(f"DEVICE: {current_device}")
            print("-" *70)

        print(
            f"[{result.status:<13}] "
            f"{result.category:<12} "
            f"{result.target:<20} "
            f"{result.message}"
        )

        if result.status != "PASS":

            if result.expected is not None:
                print(
                    f" Expected: "
                    f"{result.expected}"
                )

            if result.actual is not None:
                print(
                    f" Actual: "
                    f"{result.actual}"
                )

    print()
    print("=" *70)

    statuses = {
        "PASS": 0,
        "WARNING": 0,
        "FAIL": 0,
        "NOT_EVALUATED": 0,
    }

    for result in results:
        if result.status in statuses:
            statuses[result.status] += 1
    for status, count in statuses.items():
        print(f"{status:<15}: {count}")

    if statuses ["FAIL"] > 0:
        overall = "FAIL"

    elif statuses["NOT_EVALUATED"] >0:
        overall = "WARNING"

    elif statuses["WARNING"] >0:
        overall = "WARNING"

    else:
        overall = "PASS"

    print()
    print(f"OVERALL STATUS: {overall}")
    print("=" *70)

def save_json_report(results):
    report_directory = Path("report")
    report_directory.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    report_path = (
        report_directory
        / f"compliance_{timestamp}.json"
    )

    data = {
        "timestamp": datetime.now().isoformat(),
        "results": [
            result.to_dict()
            for result in results
        ],
    }

    report_path.write_text(
        json.dumps(
            data,
            indent=4,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(
        f"\nJSON riport elmentve: "
        f"{report_path}"
    )

    return report_path

