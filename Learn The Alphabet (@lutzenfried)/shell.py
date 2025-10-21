import requests
import json

def main():
    print("Simple Command Shell (connected to localhost:8080)")
    while True:
        try:
            cmd = input("$ ").strip()
            if cmd.lower() in {"exit", "quit"}:
                print("Exiting shell.")
                break

            url = f"http://localhost:8080?com={cmd}"
            response = requests.get(url)

            # Try to parse JSON
            try:
                data = response.json()
                if "output" in data:
                    # Decode escaped sequences like \n into real newlines
                    output = data["output"].encode("utf-8").decode("unicode_escape")
                    print(output, end="")
                else:
                    print(json.dumps(data, indent=2))
            except json.JSONDecodeError:
                print(response.text)
        except KeyboardInterrupt:
            print("\nExiting shell.")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
