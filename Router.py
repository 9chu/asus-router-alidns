import logging
import telnetlib


def get_wan_status(password, username="admin"):
    logging.info("Connecting to router")
    tn = None
    try:
        tn = telnetlib.Telnet("router.asus.com", port=23, timeout=10)
        tn.read_until(b"login: ")
        tn.write((username + '\n').encode("utf-8"))
        tn.read_until(b"Password: ")
        tn.write((password + '\n').encode("utf-8"))

        result = tn.read_until(b"# ", timeout=5)
        if b"Login incorrect" in result:
            logging.error("Bad router password")
            raise PermissionError("Bad password")

        tn.write(b"nvram get wan0_enable\n")
        tn.read_until(b"\n")
        wan0_enable = int(tn.read_until(b"\n").decode("utf-8").strip())

        tn.read_until(b"# ")
        tn.write(b"nvram get wan1_enable\n")
        tn.read_until(b"\n")
        wan1_enable = int(tn.read_until(b"\n").decode("utf-8").strip())

        result = []
        if wan0_enable != 0:
            tn.write(b"nvram get wan0_ipaddr\n")
            tn.read_until(b"\n")
            wan0_ipaddr = tn.read_until(b"\n").decode("utf-8").strip()
            result.append(wan0_ipaddr)

        if wan1_enable != 0:
            tn.write(b"nvram get wan1_ipaddr\n")
            tn.read_until(b"\n")
            wan1_ipaddr = tn.read_until(b"\n").decode("utf-8").strip()
            result.append(wan1_ipaddr)

        result.sort()
        return result
    except Exception as ex:
        logging.exception(ex)
        raise ex
    finally:
        if tn:
            tn.close()
