from zmq import Context, REQ

class Cryptol:
    ctx = Context()
    req = None

    def __init__(self, addr):
        self.req = self.ctx.socket(REQ)
        self.req.connect(addr)

    def eval(self, expr):
        self.req.send_json(None)


if __name__ == '__main__':
    cry = Cryptol("tcp://127.0.0.1:5555")
    print cry
    print cry.eval("1+1")
