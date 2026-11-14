import socket
import json
import os

HOST = "127.0.0.1"
PORT = 2323


# Create TCP socket
client_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

try:

    # Connect to server
    client_socket.connect((HOST, PORT))

    print("Connected to Telnet Server!")
    print("Type 'help' to see available commands.")
    print("---------------------------------------")

    reader = client_socket.makefile("r", encoding="utf-8")

    #Authentication

    password = input("\nEnter password: ").strip()
    # Convert command into JSON
    auth = json.dumps({
        "command": password
    }) + "\n"

    # Send command to server
    client_socket.sendall(auth.encode("utf-8"))

    # Receive server response
    res = reader.readline()
    response = json.loads(res)
    command = response["output"]

    while True:
        if command == "exit":
            break

        # Take command from user
        command = input("\nTelnet> ").strip()

        if not command:
            continue

        # Convert command into JSON
        request = json.dumps({
            "command": command
        }) + "\n"

        # Send command to server
        client_socket.sendall(request.encode("utf-8"))

        # Receive server response
        data = reader.readline()

        if not data:
            print("Server disconnected.")
            break

        response = json.loads(data)

        # Handle special responses
        output = response["output"]
        if output == "__CLEAR__":
            os.system("cls" if os.name == "nt" else "clear")
        else:
            print(output)

except ConnectionRefusedError:
    print("Unable to connect. Is the server running?")

except OSError as error:
    print("Network error:", error)

finally:
    client_socket.close()
    print("Client connection closed.")
