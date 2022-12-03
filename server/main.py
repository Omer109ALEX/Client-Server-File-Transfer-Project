import server

def read_port_number():
    try:
        with open("port.info.txt", "r") as port_file:
            port_str = port_file.readline().strip()
            port_number = int(port_str)
    except:
        print("Failed to read from file port.info, the default port is 1234")
        port_number = 1234
    finally:
        return port_number

if __name__ == '__main__':

    PORT = read_port_number()
    server_to_run = server.Server('127.0.0.1', PORT)
    server_to_run.start()



