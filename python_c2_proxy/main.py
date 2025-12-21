import time
from driver_context import DriverContext


def main():
    driver_ctx = DriverContext()
    driver_ctx.start_listening()

    print("[*] Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[*] Exiting...")


if __name__ == "__main__":
    main()
