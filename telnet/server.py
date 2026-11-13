import socket
import json

from shell import run_command

HOST = "127.0.0.1"
PORT = 2323
password = "admin"


# Create TCP socket
server_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

# Allow reuse of the port
server_socket.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

# Bind socket to IP and port
server_socket.bind((HOST, PORT))

# Listen for connections
server_socket.listen(5)

print("Telnet Server Started")
print(f"Listening on {HOST}:{PORT}")


while True:

    # Accept client connection
    conn, addr = server_socket.accept()

    with conn:
        reader = conn.makefile("r", encoding="utf-8")

        #authenticate
        data = reader.readline()
        request = json.loads(data)
        passkey = request["command"]

        if(passkey == password):
            op = "fine"
            is_exit = False
            print(f"\nClient connected: {addr}")
        else:
            op = "exit"
            is_exit = True
        
        message = json.dumps({
            "output": op
        }) + "\n"

        conn.sendall(message.encode("utf-8"))

        while True:

            # Receive command from client
            data = reader.readline()

            if not data:
                break

            try:
                if is_exit:
                    break

                request = json.loads(data)
                command = request["command"]

                print(f"Received command: {command}")

                if command == "exit":
                    response = "Disconnected from server."
                    is_exit = True
                else:
                    # Execute command through shell.py
                    response = run_command(command)
                    is_exit = False

                # Send output to client
                message = json.dumps({
                    "output": response
                }) + "\n"

                conn.sendall(message.encode("utf-8"))

            except (json.JSONDecodeError, KeyError):
                message = json.dumps({
                    "output": "Invalid request."
                }) + "\n"

                conn.sendall(message.encode("utf-8"))

    print("Client disconnected")

