# Intrustd flock protocol

Appliances connect to a flock using the flock protocol. The flock
protocol is run over UDP. Reliability is ensured via retransmissions.

# Appliance location

A flock is a collection of servers and appliances. Each server in a
flock is charged with handling some range of appliance IDs, based on
the modulus of the SHA256 hash of the normalized appliance name.

Flocks keep an in-memory map of appliance names to appliance IP/UDP
port pairs. Each pair is kept alive for a max of one minute

Appliances will ping the flock server every 30 seconds. If all
information matches, the flock will accept the request, and reset the
keep-alive timer for that pair. If information has changed, the flock
will add the new address to its mapping, and attempt to ping the old
address. If no ping is received from the old address within one minute
(or the device that responds is not the current one), then the mapping
is immediately removed and replaced.

This checking process may take longer than 30 seconds. During this
time, the flock server will not respond to ping requests. The
appliance should continue to send ping requests until a response is
given, or until its own timeout is reached (usually 10 minutes).

# Browser log-ins

Flocks also serve a websocket port. In this case, a flock will serve
the entire request, even if it does not handle appliance names for the
given range. It does this by communicating with the needed servers
itself. This increases server complexity, but makes the client flow
easy.

Upon websocket client login, the client will send the flock the name
of the device it would like to connect to. The flock will attempt to
ping that device for a list of personas. The appliance will respond
with a list of personas, or a reply indicating the persona
username/password pair has to be entered separately.

The username / profile information may be cached on the flock server
for an unbounded period of time, but the flock will check with the
appliance (via checksum) that it's information is up-to-date before
sending a response to its clients

# Connection establishment+

Once a browser client has established a device name, persona id, and
credentials. It will want to attempt login. The browser signals, via
websocket, all the information it has collected. The flock will
immediately attempt to contact the appliance via UDP.

Note that the server receiving the browser request may be different
than the one that has stored the flock ping. The server servicing the
browser is in charge of looking up the location of the appliance on
the appliance servicer and then pinging the appliance itself. Because
all servers in the same flock share a cryptographic key, the appliance
will be able to verify that the server attempting login is authorized
to do so.

The flock will continue to contact the appliance via UDP until a
response is received. The connection request will contain a nonce that
can be used to ensure idempotency in the face of network lag and
retransmission.

After the appliance has signalled a willingness to connect, ICE
candidates are exchanged. Browsers will send their ICE candidates via
websocket. Appliances will send ICE candidates via UDP requests, with
retransmits. Flocks will send ICE candidates to appliances via UDP
requests with retransmits and to browsers via websocket messages.

At some point, both appliance and flock will signal an end of
candidates. The appliance should only send an end-of-candidates signal
once it has received acknowledgment for all candidates sent.

In the meantime, ICE protocol negotiation proceeds as usual.

Once the EOC information is exchanged, the websocket is forcibly
closed by the flock. Further connection requests should be made by
logging-in again.

