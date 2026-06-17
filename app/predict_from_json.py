import sys

try:
    from .predict_from_features import parse_features, predict_features
except ImportError:
    from predict_from_features import parse_features, predict_features


def main():
    raw = sys.argv[1] if len(sys.argv) >= 2 else sys.stdin.read().strip()
    result = predict_features(parse_features(raw))
    print(result["status"])


if __name__ == "__main__":
    main()
