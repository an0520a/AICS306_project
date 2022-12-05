import multiprocessing as mp
import time
from multiprocessing import connection

def test(pipe : connection.PipeConnection):
    poll_val = None
    while(True):
        if pipe.poll():
            pipe.recv()
            print("recv")
            pipe.close()

            return
        else:
            print("wait")

        time.sleep(1)

def main():
    recv_pipe, send_pipe = mp.Pipe(False)
    p = mp.Process(name="Sub", target=test, args=(recv_pipe,))
    p.start()
    
    time.sleep(5)

    send_pipe.send(5)
    send_pipe.close()

    p.join()

if __name__ == "__main__":
    main()