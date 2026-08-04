"""finacle-bridge — the core banking connector.

Team: core-banking. SOAP over TLS, because that is what a core banking platform
of this generation exposes and what a bank's connector layer actually speaks.

Four operations behind one URL. The URL is the transport; the operations are the
API surface, and the kernel probe records them as `<path>#<Operation>` from the
SOAPAction header so a registry describes forty operations rather than one
endpoint.

The WSDL is served at ?wsdl and is what the legacy collector parses. It is the
same document a client would fetch — there is no second copy of the interface
inventory maintained for SENTRY's benefit.
"""

from estate_app import app, health, rng

SERVICE_PATH = "/finacle/CustomerService"
TARGET_NS = "http://finacle.corebank.internal/customer"

OPERATIONS = ["GetCustomerBalance", "GetCustomerKyc", "PostLedgerEntry",
              "GetNostroPosition"]


@app.get(SERVICE_PATH)
def wsdl() -> str:
    """The interface contract, as a client fetches it.

    ``?wsdl`` is not a separate route: http.server hands the query string with
    the path, and both a bare GET and a GET with ?wsdl arrive here.
    """
    ops = "\n".join(
        f'''    <operation name="{op}">
      <input message="tns:{op}Request"/>
      <output message="tns:{op}Response"/>
    </operation>''' for op in OPERATIONS)

    bindings = "\n".join(
        f'''    <operation name="{op}">
      <soap:operation soapAction="{op}"/>
      <input><soap:body use="literal"/></input>
      <output><soap:body use="literal"/></output>
    </operation>''' for op in OPERATIONS)

    messages = "\n".join(
        f'''  <message name="{op}Request"><part name="body" element="tns:{op}"/></message>
  <message name="{op}Response"><part name="body" element="tns:{op}Response"/></message>'''
        for op in OPERATIONS)

    return f'''<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="{TARGET_NS}"
             targetNamespace="{TARGET_NS}">
{messages}
  <portType name="CustomerServicePortType">
{ops}
  </portType>
  <binding name="CustomerServiceBinding" type="tns:CustomerServicePortType">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
{bindings}
  </binding>
  <service name="CustomerService">
    <port name="CustomerServicePort" binding="tns:CustomerServiceBinding">
      <soap:address location="https://finacle-bridge:8443{SERVICE_PATH}"/>
    </port>
  </service>
</definitions>'''


@app.soap(SERVICE_PATH)
def customer_service(action: str) -> str:
    """One handler, dispatching on SOAPAction.

    Responses carry Indian financial identifiers so the in-kernel data-class
    detection has something to find on a SOAP path as well as a JSON one — the
    detector reads bytes and does not care which envelope they arrived in.
    """
    account = f"{rng.randint(10**11, 10**12 - 1)}"
    if action == "GetCustomerKyc":
        payload = (f"<aadhaar>{rng.randint(10**11, 10**12 - 1)}</aadhaar>"
                   f"<pan>ABCDE1234F</pan><status>VERIFIED</status>")
    elif action == "PostLedgerEntry":
        payload = f"<reference>LDG{rng.randint(10**6, 10**7)}</reference><posted>true</posted>"
    elif action == "GetNostroPosition":
        payload = (f"<nostroAccount>{account}</nostroAccount>"
                   f"<ifsc>HDFC0{rng.randint(100000, 999999)}</ifsc>"
                   f"<position>{rng.randint(10**5, 10**7)}.00</position>")
    else:
        payload = (f"<accountNumber>{account}</accountNumber>"
                   f"<ifsc>HDFC0{rng.randint(100000, 999999)}</ifsc>"
                   f"<balance>{rng.randint(1000, 900000)}.00</balance>")

    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<soap:Body><ns:{action or "Unknown"}Response xmlns:ns="{TARGET_NS}">'
            f'{payload}</ns:{action or "Unknown"}Response></soap:Body></soap:Envelope>')


@app.get("/healthz")
def healthz() -> dict:
    return health()
