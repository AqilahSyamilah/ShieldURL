try:
    from .train_model import main
except ImportError:
    from train_model import main


if __name__ == "__main__":
    main()
