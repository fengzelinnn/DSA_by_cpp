2021 IEEE 21st International Conference on Software Quality, Reliability and Security Companion (QRS-C)

Modeling and Veriﬁcation of CKB Consensus
Protocol in Coq

Xiaokun Luan
School of Mathematical Sciences
Peking University
Beijing, China
luanxiaokun@pku.edu.cn

Meng Sun
School of Mathematical Sciences
Peking University
Beijing, China
sunm@pku.edu.cn

Abstract—Blockchain has been prospering for the last decade.
Despite the tremendous success of blockchain, it is still vulnerable
due to the complexity of distributed execution environment.
Malicious attacks that exploit these vulnerabilities can lead to
serious losses. Common Knowledge Base (CKB) is a public
permissionless blockchain and the base layer of Nervos Network,
which is gaining popularity in recent years. It adopts a novel con-
sensus protocol to overcome two shortcomings of Bitcoin: the low
transaction processing throughput and the vulnerability to selﬁsh
mining attacks. Considering the high-security requirements in
CKB application scenarios, it is essential to provide formalization
and veriﬁcation of the safety and security properties of the CKB
blockchain. In this paper, we provide a formal model of CKB
consensus protocol
in the theorem prover Coq. Fundamental
components of the protocol are implemented, including the block
structure, the two-step transaction conﬁrmation mechanism, and
the peer-to-peer asynchronous network. We also use Coq to
establish the quiescent consistency property of the consensus
protocol, which is a kind of eventual consensus that all the
participants agree on the same ledger when there are no inﬂight
messages.

Index Terms—theorem proving, blockchain, consensus protocol

I. INTRODUCTION

Blockchains have attracted extensive attention since Satoshi
Nakamoto created Bitcoin [1]. A blockchain is a decentralized
distributed ledger containing transaction records packed as
blocks. Changing a recorded transaction requires altering all
subsequent blocks, so blockchains are resistant
to modiﬁ-
cation. As a result of the advantages of decentralization,
persistence, and traceability, blockchains are widely used in
cryptocurrencies [2], smart contracts [3], ﬁnancial services [4],
and healthcare [5], etc. However, blockchain technology suf-
fers from cybersecurity vulnerabilities which can cause great
loss. For example, a digital decentralized autonomous organi-
zation, the DAO, was subject to an attack that exploited the
vulnerability, resulting in a loss of more than 50M USD in
the transfer of a large number of tokens [6]. It is therefore
increasingly important to ensure the security and safety of
blockchains.

The Nervos Network [7]

is an open-source public
blockchain ecosystem with a two-layer architecture. The ﬁrst
layer, called Common Knowledge Base (CKB) layer, is a
public blockchain designed to overcome two drawbacks of

Bitcoin: the low transaction processing throughput and the
vulnerability to selﬁsh mining attack [8]. The core idea to
overcome these two shortcomings is to decouple the proposal
and commitment of transactions. CKB consensus protocol [9]
adopts a two-step transaction conﬁrmation to improve the
throughput and uses a novel dynamic difﬁculty adjustment
mechanism to make the selﬁsh-mining attack non-proﬁtable.
The popularity of the CKB blockchain has been growing
in recent years due to its scalability and efﬁciency. Therefore,
ensuring the security and safety of CKB blockchain, especially
the consensus protocol is becoming more and more important.
Formal veriﬁcation techniques have been successfully applied
to provide safety assurance of blockchain. For example, [10]
veriﬁed asynchronous safety of the Algorand [11] consensus
protocol by theorem proving, and [12] also used theorem
proving technique to develop a framework to formalize and
verify proof of work blockchain consensus protocol. Although
CKB blockchain also adopts proof of work mechanism to
reach consensus,
the framework proposed in [12] cannot
deal with CKB consensus protocol because of its different
block structure and novel two-step conﬁrmation mechanism.
Therefore, it is still necessary to investigate the security of the
CKB consensus protocol.

In this paper, we present our framework for formal modeling
and veriﬁcation of CKB consensus protocol by the means
of theorem proving. The consensus protocol is modeled as
a transition system in the theorem prover Coq [13]. The block
structure, the two-step transaction conﬁrmation mechanism,
and the peer-to-peer network are formalized in Coq. The
mining process and the blockchain fork are modeled by a set
of axioms. We also give operational semantics of the transition
system, based on which we establish several properties of the
consensus protocol. The most important property proved in
Coq is the quiescent consistency property [14], which is a kind
of eventual consensus that all nodes agree on the same ledger
when there are no inﬂight messages. This property is proved
by establishing an invariant that we call consensus invariant.

Our contribution is summarized as follows.
1) A formal model of CKB consensus protocol in Coq,

where the fundamental components are modeled.

2) Operational semantics of the transition system, including
local semantics for each node in the network and global

2693-9371/21/$31.00 ©2021 IEEE
DOI 10.1109/QRS-C55045.2021.00100
Authorized licensed use limited to: Institute of Information EngineeringCAS. Downloaded on December 08,2024 at 08:14:19 UTC from IEEE Xplore.  Restrictions apply.

660

.

.

0
0
1
0
0
1
2
0
2
5
4
0
5
5
C
-
S
R
Q
/
9
0
1
1
0
1
:
I

.

O
D
|
E
E
E
I

.

1
2
0
2
©
0
0
1
3
$
/
1
2
/
6
-
6
3
8
7
-
4
5
6
6
-
1
-
8
7
9
|
)
C
-
S
R
Q

i

(
n
o
n
a
p
m
o
C
y
t
i
r
u
c
e
S
d
n
a
y
t
i
l
i

b
a

i
l

e
R

,
y
t
i
l

a
u
Q
e
r
a
w

t
f
o
S
n
o
e
c
n
e
r
e
f
n
o
C

l

a
n
o
i
t
a
n
r
e
t
n

I

t
s
1
2
E
E
E
I

1
2
0
2

semantics for the whole network system.

3) An eventual consistency property for the CKB consensus
protocol, established by proving a system invariant under
certain assumptions.

The rest of this paper is organized as follows: In Section II,
we provide a more detailed description of Nervos Network
and the CKB consensus protocol. Section III presents the
formal model in Coq, explaining in detail the fundamental
components. The veriﬁcation process in Coq is elaborated in
Section IV. In Section V, we brieﬂy review related work
on this topic. Finally Section VI concludes the paper and
discusses some future research directions.

II. THE CKB CONSENSUS PROTOCOL

In this section, we provide an introduction of Nervos Net-
work, explain the two-layer architecture design, and describe
the CKB consensus protocol in detail. The assumptions used
in our model are also discussed.

A. Nervos Network

Although Bitcoin is the most popular cryptocurrency, its
throughput is far from satisfactory and it is also prone to
selﬁsh mining attack. Nervos Network is proposed to over-
come these two drawbacks, it uses a two-layer architecture,
as shown in Figure 1, to improve the scalability and provide
better user experience. The ﬁrst layer is Common Knowledge
Base (CKB) layer, serving as the foundation of security and
decentralization. Assets storage and state veriﬁcation are also
done by the CKB layer. The second layer is responsible for
generating transactions at a very high speed and protecting
privacy, mainly focusing on scalability. The two layers work
together to achieve higher levels of decentralization, security,
and scalability. There are three kinds of nodes in Nervos Net-
work, including (1) mining nodes, responsible for collecting
transactions and creating blocks, (2) full nodes, responsible for
veriﬁcation, and (3) light nodes, that only download blocks.
All nodes can enter and exit the network freely at any time.

Fig. 1. The Nervos Network layered architecture

B. CKB Consensus Protocol

The CKB consensus protocol [9] aims to improve the
throughput and enhance the security of the blockchain. The
main idea is to decouple the transaction conﬁrmation into

proposal step and commitment step. The CKB consensus
protocol is composed of the following elements:

1) Block structure: A block in the CKB blockchain in-
cludes a pointer to its previous block, a proof object, a
proposal zone, and a commitment zone. The proof object
allows nodes to independently verify the legitimacy of the
block. The proposal zone is used to facilitate transaction
synchronization, it contains the truncated hashes of proposed
transactions. The truncated hash is deﬁned as the ﬁrst few
bits of its hash. The commitment zone contains hashes of
committed transactions.

2) Two-Step Transaction Conﬁrmation: Conﬁrmation of a
transaction consists of the proposal step and the commitment
step. In the proposal step, the transaction is collected by a
mining node, and its truncated hash is put into the proposal
zone. Any transaction whose truncated hash is within the
proposal zone is regarded as proposed, even if there may be
collision. Transactions in the proposal zone do not affect the
validity of the block, so a node can start transferring the block
to its neighbors before receiving these transactions. In the
commitment step, the transaction is committed if it appears
in the commitment zone of a block in a window starting
several blocks after its proposal. More formally, a transac-
tion is committed at height hc if the following conditions
are met: (1) the transaction is proposed at height hp and
wclose ≤ hc − hp ≤ wf ar where wclose and wf ar are two
parameters; (2) the transaction is in the commitment zone at
height hc; (3) the transaction does not conﬂict with its previous
committed transactions.

3) Peer-to-peer Network: In CKB network, a set of stateful
nodes communicate with each other through a peer-to-peer
network in an asynchronous message passing fashion. The goal
of these nodes is to maintain and extend a distributed ledger
which consists of a sequence of blocks forming a chain. The
state of a node consists of the address used for cryptographic
operations and message delivery, the address of its peer nodes,
a transaction pool containing all the unconﬁrmed transactions,
and all blocks received by the node, even if it does not appear
in the ledger, to prevent the ledger from changing to another
chain. There are ﬁve normal operations for a node: (1) generate
a new transaction, add this transaction to the pool and then
broadcast it; (2) create a new block and then broadcast it; (3)
receive a transaction and add it to the pool, if the transaction
has never been seen before then broadcast it; (4) receive a
block and validate it, broadcast it if the block has a valid
proof object; (5) request unknown transaction from the sender,
or answer someone’s request. In most cases, when a node
receives a new block, this node already has all the transactions
in the commitment zone in his memory thanks to the proposal
step. However, in Byzantine scenarios, there may be unknown
transactions in the commitment zone, for example due to lost
messages or malicious actions. In this situation, the receiver
will request the sender for the missing transactions with a
short timeout. If the sender cannot provide all the missing
transactions in time, then the receiver will add the sender to
its blacklist.

Authorized licensed use limited to: Institute of Information EngineeringCAS. Downloaded on December 08,2024 at 08:14:19 UTC from IEEE Xplore.  Restrictions apply.

661

4) Dynamic Difﬁculty Adjustment Mechanism: Besides the
two-step transaction conﬁrmation, CKB consensus protocol
also has a dynamic adjustment mechanism to make selﬁsh
mining attacks non-proﬁtable. The protocol incorporates all
blocks, instead of only the main chain, in estimating the hash
rate to dynamically adjust the difﬁculty. Details about this
mechanism are not presented here since it is orthogonal to
the consensus property we are going to establish in the paper.

C. Model Assumptions

Now we discuss several assumptions on which our mod-
elling is based. Some of these assumptions remove the parts
of the protocol that are not relevant to consensus property
to simplify the model. Our model assumptions are listed as
follows.

1) Finite nodes: There is a ﬁnite number of nodes, and they

will not exit the network.

2) Clique topology: Every node knows all the other nodes

from the beginning.

3) No distinction between node types: Three kinds of nodes

are not distinguished.

4) No hash collisions: The hash function does not collide.

The ﬁrst assumption removes the scenarios when a new
node enters the network and needs to catch up with the global
state of the system. Although this is not uncommon, such
as nodes going ofﬂine for a while and then coming back,
it is orthogonal to the eventual consensus of our interest.
The second assumption, although seemingly quite strong, is
actually very common. Adopting a non-clique connected graph
is possible, but this would result in a more complex model
and make it more difﬁcult to verify. The third assumption
simpliﬁes node behavior, nodes in our model are responsible
for both block mining and transaction veriﬁcation, but the
consensus property will be preserved. The last assumption
is reasonable since hash collision is probabilistically rare
in practice, and it is a common assumption in many other
veriﬁcation frameworks.

III. FORMAL MODEL OF CKB CONSENSUS PROTOCOL

In this section, we present

the formal model of CKB
consensus protocol in Coq. We use a transition system to
model the CKB consensus protocol. The parameters and data
structure used in the model, the local semantics and global
semantics are speciﬁed. More details about the model and
proofs in Coq are available online at [15].

A. Parameters and Data Structures

1) Primitive Types and Functions: Modeling CKB consen-
sus protocol in Coq requires making assumptions about the

primitive types, shown as follows.

Time := N
Address : finType
Transaction : eqType
HashValue : eqType
ProofValue : eqType

hashB : Block → HashValue
hashT : Transaction → HashValue
hashPID : Transaction → HashValue

The type of time stamps Time is deﬁned as natural numbers
N because they are isomorphic. Since we assume that there
is a ﬁnite number of nodes in the network, the type of node
address Address is assumed to be finType, which means the
underlying implementation of node address can be arbitrary
as long as the number of addresses is ﬁnite. The type of
transactions Transaction, the type of hash value HashValue,
and the type of proof object ProofValue are all eqType.
Similarly, the implementation of these objects can be arbitrary
as long as we can decide equality on these types (finType can
be viewed as a subtype of eqType, so we also have decidable
equality on node address).

Three hash functions are deﬁned to calculate the hashes of
blocks (hashB), the hashes of transactions (hashT), and trun-
cated hashes of proposed transactions (hashPID), respectively.
Since we assume no hash collisions, hashB and hashT are
injective functions.

hashB_injective : ∀x y, hashB x = hashB y → x = y
hashT _injective : ∀x y, hashT x = hashT y → x = y

On the other hand, we allow hashPID to collide, so there is
no axiom about hashPID. For the sake of brevity, we use #x
to denote the hash of x whenever the type of x is clear, and
use ##t to denote the truncated hash of transition t.

2) Block and Blockchain: The deﬁnitions of data structures

being used in our model are presented as follows.

Block := { prev : HashValue;

comm_txs : seq HashValue;
prop_txs : seq HashValue;
proof : ProofValue}

BlockChain := seq Block

BlockMap := {fmap HashValue → Block}

GB : Block

Block is a structure with four ﬁelds: prev for the hash value
of the previous block, comm_txs for the committed zone,
prop_txs for the proposal zone, and proof for the proof
object of the block. The “seq Block” in the deﬁnition of
BlockChain refers to the sequence of blocks, and the “seq
HashValue” in the deﬁnition of Block is similar. BlockMap is
deﬁned to be a partial ﬁnite map from block hash values to
blocks, serving as a container to store blocks in memory.

Authorized licensed use limited to: Institute of Information EngineeringCAS. Downloaded on December 08,2024 at 08:14:19 UTC from IEEE Xplore.  Restrictions apply.

662

The ﬁrst block in the CKB blockchain is called genesis
block, which is modeled by GB in our model. Further, we
assume that GB is initially globally shared by all nodes. Here
we have several axioms about genesis block.

GB_nil : comm_txs GB = [] ∧ prop_txs GB = []

GB_hash : prev GB = #GB

nonGB_hash : ∀b, b (cid:6)= GB → prev b (cid:6)= #b

First, GB_nil ensures that there is no transactions in GB.
Second, GB_hash imposes that the previous block of GB is
itself, ensuring that there is no parent block of GB. The third
axiom nonGB_hash is a technical axiom to eliminate self-
looping block, which is infeasible and unproﬁtable in practice.
We call a BlockChain object well-formed if all the blocks in
it actually form a chain. Similarly, we call a BlockMap object
valid if each entry is of the form #b (cid:7)→ b and #GB (cid:7)→ GB is
contained in the map. For the sake of brevity, we use b ∈ bm to
denote that the mapping #b (cid:7)→ b is contained in the block map
bm, and use bm (cid:2) b to denote the result of updating bm with the
mapping #b (cid:7)→ b. Further, for a blockchain c = [b1; · · · ; bn],
we deﬁne bm (cid:2) c as (((bm (cid:2) b1) (cid:2) · · ·) (cid:2) bn). It is easy to
show that the (cid:2) operator preserves the property of validity.
Therefore, we assume that all the block maps we are going to
deal with are valid, unless stated otherwise.

Generating a block requires a proof object, this can be done

by the genPf function in our model, formalized as:

genPf : Address → BlockChain → Time
→ option ProofValue

The proof object is obtained by passing the node address, the
local ledger, and a time stamp to this function where the time
stamp serves as a seed. Since the return value is of type option
ProofValue, the return value of this function is not always a
proof object, but may also be a none object so that the node
has to call this function another time with different seeds,
thus modeling the mining process. The process of checking
the validity of a proof object is abstracted as follows:

validPf : Block → bool

GB_valid : validPf GB = true

The function validPf works together with genPf. It unpacks
the input block to get its proof and checks the validity of the
proof. Besides, we also assume validPf GB is true for self-
consistency, as the axiom GB_valid states.

3) Transaction Validity: Functions for checking transaction
validity are slightly more complex than that for proof validity
due to the proposal step. We use a function txsComp to check
transaction compatibility. A transaction is compatible with a
blockchain if it does not conﬂict with any transaction in the
commitment zone in the blockchain.

txsComp : Transaction → BlockChain → bool

The other function txsValid deﬁnes the validity of a transac-
tion in the commitment zone. A transaction in the commitment

zone of a block at height hc is valid if it is compatible with the
previous blockchain (corresponds to txsComp tx bc) and it is
proposed at height hp of the chain where wclose ≤ hc − hp ≤
wf ar (corresponds to ##tx ∈ (slice bc wclose wf ar)). hc
is the current height of the blockchain and wclose and wf ar
are parameters.

txsValid tx bc := (txsComp tx bc) &&

(##tx ∈ (slice bc wclose wf ar))

Transaction validity is deﬁned in terms of transactions, we
can extend it to blockchain. A blockchain c = [b1; · · · ; bn] is
said to be valid in terms of transactions if all the commitment
transactions in c are valid, i.e. for all bi ∈ c, for any transaction
tx in the commitment zone of bi, txsValid tx [b1; · · · ; bi−1]
holds.

B. Computing Local Ledger

It is possible that two different nodes create two different
blocks to extend the same chain. Such situation is called a fork,
which is why a node stores all blocks in the memory even they
are not in the ledger. The inconsistency can be eliminated by
a globally known Fork Choice Rule (FCR) [12] that imposes
a strict total order on all possible chains of blocks. Each node
always adopts the greatest blockchain as its local ledger. This
total order is formalized as a parameter in our model, since
we do not care about the underlying implementation as long
as the following axioms are satisﬁed.

F CR : BlockChain → Blockchain → bool

F CR_nref l : ∀c, ∼ c ≺ c
F CR_tran : ∀c1 c2 c3, c1 ≺ c2 → c2 ≺ c3 → c1 ≺ c3
F CR_total : ∀c1 c2, c1 ≺ c2 ∨ c1 = c2 ∨ c2 ≺ c1
F CR_sub : ∀c b, c ≺ c ++ (b :: nil)

We use c1 ≺ c2 to denote that c2 is greater than c1 under
the FCR relation. The ++ operator is list concatenation. The
:: operator is appending an element to the head of the list,
and nil is the constructor for an empty list. The ﬁrst three
axioms ensure that FCR is a strict total order, i.e. satisfying
irreﬂexivity, transitivity, and totality. The last axiom states that
appending a block to the tail of a chain results in a greater
chain, which is the most essential characteristic of FCR.

With FCR, we can calculate the greatest chain starting from
GB in the block map bm, which is deﬁned as the local ledger,
or the main chain of the node, denoted as [bm]. Put it more
formally, [bm] is deﬁned as the largest blockchain (wrt. FCR)
that satisﬁes the following properties:

1) All the blocks are contained in bm.
2) All the blocks form a chain structure.
3) GB is the ﬁrst block in the chain.
4) The blockchain is valid in terms of transactions.

In our formal model, we ﬁrst use a depth-ﬁrst search to
enumerate all main chain candidates from the block map and
then get the greatest blockchain, thus we get the local ledger.

Authorized licensed use limited to: Institute of Information EngineeringCAS. Downloaded on December 08,2024 at 08:14:19 UTC from IEEE Xplore.  Restrictions apply.

663

C. Local Semantics

Nodes communicate by passing messages to broadcast
transactions, propagate blocks, and request missing transac-
tions. We therefore divide the messages into three categories
for passing blocks (BlkMsg), passing transactions (TxsMsg),
and requesting transactions (ReqMsg). The message, together
with its source and destination, are packed into a packet,
deﬁned as:

Message := BlkMsg (b : Block)

| TxsMsg (ts : seq Transaction)
| ReqMsg (hs : seq HashValue)

Packet := {src : Address;
dst : Address;
msg : Message}

For the sake of brevity, we use (f rom, to, msg) to denote a
packet.

In our model, we use a local state LState to represent the
state of a node. A local state consists of the node address, the
peers, the local block map, and the local transaction pool.

LState := {addr : Address;

prs : seq Address
bmap : BlockMap;
txpool : seq Transaction}

We use q = (cid:12)a, prs, bmap, tp(cid:13) to denote a local state. The
initial local state q0 contains the address of the node a0, a
singleton block map bmap0 = {#GB (cid:2) GB} and an empty
transaction pool tp0 = []. Since we assume a clique network
topology, prs0 include the addresses of all the other nodes.

There are two kinds of actions that can change the state
of a node: message delivery and internal transition. Message
delivery consumes a message and changes the state of a node,
after that the node may generate some new messages. Internal
transition can take place without consuming any messages.
p−→ (q(cid:2), ps) to
For message delivery, we use the notation q
represent the transition from local state q to q(cid:2), where the
packet p is consumed and a sequence of packets ps (possibly
t−→τ (q(cid:2), ps) represents the
empty) is emitted. The notation q
internal transition from local state q to q(cid:2) at the global time t,
also emitting a sequence of packets ps.

The semantics rules for message delivery are as follows.
There are three rules for message delivery, corresponding to
three types of messages. The premises of RCVBLK ensure
that only when the block received is valid in terms of both
transactions and proof will the node broadcast it to the peers.
If there is any unseen transaction in the proposal zone or
commitment zone, according to the CKB consensus protocol,
then the receiver will request these missing transactions from
the message sender. The RCVTXS rule states that if a node
receives transactions that have never been seen before, then
it will propagate these new transactions, otherwise it does
nothing. The premises of RCVREQ ensure that when a node is

requested for some missing transactions, it gives the requestor
all the possible transactions, despite that there may be collision
for truncated hash values.

RCVBLK

validPf b = true
missing = {h ∈ comm_txs b | h /∈ {#tx | tx ∈ tp}}
tp(cid:2) = {tx ∈ tp | txsComp tx [bm (cid:2) b]}
comm = {tx ∈ tp | #tx ∈ comm_txs b}
(cid:2)

(cid:3)

ps1 =

ps2 =

if missing = ∅ ∧ txsValid comm [bm]
then{(cid:12)a, d, BlkMsg b(cid:13) | d ∈ prs} else ∅
(cid:3)
(cid:2)
if missing (cid:6)= ∅
then {(a, s, ReqMsg missing)}else ∅

ps3 = {(a, s, ReqMsg (prop_txs b))}
ps = ps1 ∪ ps2 ∪ ps3
(s,a,BlkMsg b)
−−−−−−−−→ ((cid:12)a, prs, bm (cid:2) b, tp(cid:2)(cid:13) , ps)

(cid:12)a, prs, bm, tp(cid:13)

RCVTXS

(cid:2)

ps =

tp(cid:2) = tp ∪ ts

if tp(cid:2) (cid:6)= tp
then {(a, d, TxsMsg ts) | d ∈ prs} else ∅

(cid:3)

(cid:12)a, prs, bm, tp(cid:13)

(s,a,TxsMsg ts)
−−−−−−−−−→ ((cid:12)a, prs, bm, tp(cid:2)(cid:13) , ps)

RCVREQ

txs = {tx ∈ tp | #tx ∈ hs ∨ ##tx ∈ hs}
ps = (a, s, TxsMsg txs)

(cid:12)a, prs, bm, tp(cid:13)

(s,a,ReqMsg hs)
−−−−−−−−−→ ((cid:12)a, prs, bm, tp(cid:13) , ps)

The semantics rules for internal transitions are as follows.
The case for generating transactions (INTTXS) is straightfor-
ward, but the case for creating a new block (INTMINT) is more
complicated. The node creates a new blocking by ﬁrst calling
the genPf to get a proof object, then it packs all the valid
transactions in its pool into the commitment zone, and packs
other compatible transactions into the proposal zone. Finally,
the new block is broadcasted.

INTTXS

tp(cid:2) = tp ∪ txs
ps = {(a, d, TxsMsg txs) | d ∈ prs}
(cid:12)a, prs, bm, tp(cid:13) t−→τ ((cid:12)a, prs, bm, tp(cid:2)(cid:13) , ps)

INTMINT

genPf a [bm] t = Some pf
ts = {tx ∈ tp | txsValid tx [bm]}

cts = {#tx | tx ∈ ts}

pts = {##tx | tx ∈ tp \ ts}

b = {prev := #(last [bm]); comm_txs := cts;

prop_txs := pts; proof := pf }

tp(cid:2) = {tx ∈ tp | txsComp tx [bm (cid:2) b]} \ts
ps = {(cid:12)a, d, BlkMsg b(cid:13) | d ∈ prs}
(cid:12)a, prs, bm, tp(cid:13) t−→τ ((cid:12)a, prs, bm (cid:2) b, tp(cid:2)(cid:13) , ps)

D. Global Semantics

We use global state to represent the state of the whole
network. A global state consists of a partial map from node

Authorized licensed use limited to: Institute of Information EngineeringCAS. Downloaded on December 08,2024 at 08:14:19 UTC from IEEE Xplore.  Restrictions apply.

664

address to its corresponding local state, all inﬂight packets,
and history messages.

blocksF or(a, Q) = [ ], then there exists a blockchain c, such
that ledger(a, Q) = c for every node a.

GState := {nodes : {fmap Address → LState};

inflight_msg : seq Packet;
consumed_msg : seq Packet}

For simplicity, we use Q = (cid:12)M, P, H(cid:13) to denote a global
state. The inflight_msg and consumed_msg parts of initial
state Q0 are both empty, and the nodes part maps each node
address to the corresponding initial local state.

There are three rules of global semantics, representing the
cases that the system is idling, or a packet is delivered, or an
internal transition takes place:

IDLE

(cid:12)M, P, H(cid:13) −→ (cid:12)M, P, H(cid:13)

DELIVER

address q = a

p ∈ P
(cid:12)M, P, H(cid:13) −→ (cid:12)M [a (cid:7)→ q(cid:2)] , P ∪ ps, H ∪ {p}(cid:13)

p−→ (q(cid:2), ps)

q

INTERNAL

address q = a

t−→τ (q(cid:2), ps)

q

(cid:12)M, P, H(cid:13) −→ (cid:12)M [a (cid:7)→ q(cid:2)] , P ∪ ps, H(cid:13)

We use Q −→ Q(cid:2) to represent that the global state Q changes
to Q(cid:2), and use Q (cid:2) Q(cid:2) to represent the transitive and reﬂexive
closure of the global transition relation, i.e. Q(cid:2) is reachable
from Q, if one of the following three conditions is met: (1)
Q(cid:2) = Q, (2) Q −→ Q(cid:2), (3)∃Q(cid:2)(cid:2), (Q (cid:2) Q(cid:2)(cid:2)) ∧ (Q(cid:2)(cid:2) (cid:2) Q(cid:2)).

IV. VERIFICATION IN COQ

The quiescent consistency [14] is the main result of our
veriﬁcation. Informally, the quiescent consistency states that
when there are no inﬂight messages, all nodes should agree
on the same local ledger. Although in practice communication
never stops, if we consider only all messages before a par-
ticular point in time, we can still know that the system will
reach consensus when all these messages are ﬁnally delivered,
without taking the modiﬁcations to the ledger by subsequent
messages into account. To put it more formally, we need the
following notations to denote the local ledger of a node and
blocks that are inﬂight to a node.

1) ledger(a, Q) is deﬁned as the local ledger of the node

a in the global state Q.

2) blocksF or(a, Q) is the list of blocks to be sent to the
node a that are still inﬂight in the global state Q.
3) valid(bm) stands for that bm is a valid block map.
4) tree(bm) stands for that blocks in bm form a tree.
5) comp(bm) holds when each blockchain in bm is valid

in terms of transactions.

Now the quiescent consistency property can be formulated as
follows.

Deﬁnition 1 (Quiescent consistency). For a global state Q
for every node a,
reachable from the initial state Q0,

if

Note that we require the global state Q reachable from
the initial state Q0, since we only care about such system
there is no
conﬁgurations. Besides, we only require that
inﬂight blocks for the node, since other kinds of messages do
not contribute to the local ledger. The quiescent consistency
property can be viewed as an inductive invariant of the system,
which not only holds for the initial state, but also is preserved
by transitions, i.e.

I(Q0) ∧ ((I(Q) ∧ Q (cid:2) Q

(cid:2)) → I(Q

(cid:2)))

(1)

where I is the invariant. The quiescent consistency invariant
can be derived from a stronger invariant, which we call the
consensus invariant, deﬁned as follows.

Deﬁnition 2 (Consensus invariant). For a global state Q, there
exists a canonical block map bm, a canonical blockchain c,
and a canonical node a, satisfying the following properties

1) ledger(a, Q) = c,
2) valid(bm), tree(bm), comp(bm), and
3) For any node a, ledger(a, Q) (cid:16) c,
4) For any node a and its block map bm, bm (cid:2)

(cid:5)
bm

= c,

(cid:4)

blockF or(a, Q) = bm.

The proof of consensus invariant implying quiescent con-
sistency is quite simple. When there are no inﬂight blocks for
any nodes, all nodes have the same block map according to
the forth requirement of consensus invariant. It follows that
all nodes have the canonical blockchain as their local ledger
according to the second requirement. Therefore, it sufﬁces to
show that the consensus invariant holds.

A. Proof of Consensus Invariant

The proof of the consensus invariant is given in two steps:
First, this property holds for the initial state Q0. Second, this
property is also preserved by transitions. Clearly this property
holds for the initial state where every node’s block map is
a singleton map {#GB (cid:7)→ GB} and there is no inﬂight
message. So we now focus on proving the second point.

The overall idea is proving by case analysis, that is to say,
for the global transition Q −→ Q(cid:2), consider all possible cases,
including idling (IDLE), message delivery (DELIVER), and
internal transition (INTERNAL). The idling case is the most
trivial since the state does not change. Cases for receiving
transactions (RCVTXS), receiving requests (RCVREQ), gener-
ating new transactions (INTTXS) are also trivial, all of which
can be proved within about 15 lines of codes in Coq. This is
because no blocks inﬂight are consumed nor new blocks are
emitted. Thus, we are left with two cases: receiving block and
creating new block.

For the receiving block case, we need a few lemmas to help
us reason about the local ledger. A central lemma we need is
that when a block is added to a block map, the local ledger is
greater than or equal to the original ledger, stated as follows:

Authorized licensed use limited to: Institute of Information EngineeringCAS. Downloaded on December 08,2024 at 08:14:19 UTC from IEEE Xplore.  Restrictions apply.

665

Lemma 1. If a block map bm is valid, then for any block b,
[bm] (cid:16) [bm (cid:2) b].

Though this lemma seems quite trivial, it requires tedious
proofs in Coq. Based on this lemma, we can get other lemmas
that can help us deal with the receiving block case, such as
the following two lemmas:
Lemma 2. If a block map bm is valid, b ∈ c, and [bm] =
[bm (cid:2) c], then [bm] = [bm (cid:2) b].
Lemma 3. If a block map bm is valid, b ∈ c, [bm] (cid:16) c(cid:2), and
[bm (cid:2) c] (cid:16) c(cid:2), then [bm (cid:2) b] (cid:16) c(cid:2).

The case that the receiver is not the canonical node is easy to
solve since the canonical block map and canonical blockchain
are not changed and we have inductive hypotheses. If the
receiver is the canonical node, we can show that the newly
received block belongs to blocksF or(a, Q), and with the help
of the above lemmas, we can show that the four requirements
of the property is preserved in the receiving block case.

In the creating new block case, we have to consider if the
newly created block contributes to the canonical blockchain,
i.e. whether [bm (cid:2) bnew] (cid:16) c, where bm is the block map of the
miner. If so, the canonical blockchain c will not change, and
bm (cid:2) bnew will become the new canonical block map, which is
a trivial case just as before. The case where c ≺ [bm (cid:2) bnew],
however, is non-trivial. In this case, the miner becomes the
new canonical node, the canonical block map should be the
original one extended with the new block, and the canonical
blockchain should be the updated local ledger of the miner. A
number of lemmas are needed to complete the proof in this
case, also the last case. For the sake of brevity, we will only
show how one of these lemmas helps us to complete the proof.
This lemma is stated as follows:

Lemma 4. For valid block maps bm and cbm, if we have
tree(cbm), comp(cbm), tree(cbm(cid:2)b), comp(bm(cid:2)b), [cbm] ≺
[bm (cid:2) b], and cbm = bm (cid:2) c for some blockchain c, then
[bm (cid:2) b] = [cbm (cid:2) b].

The cbm block map in this lemma corresponds to the
canonical block map bm. With the help of several other
lemmas, we can show that all of the preconditions of this
lemma is met, thus we can prove the second requirement
(cid:5)
(cid:4)
bm

= c.

B. Discussion on Other Properties

We mainly focus on the safety of the CKB network, other
properties like stronger safety properties and liveness are not
considered in this paper. Actually, proving stronger safety
property such as Byzantine Fault Tolerance (BFT), arbitrary
connected network topology, or allowing nodes going ofﬂine
or joining late, requires a much more complicated model than
what we provide, and the veriﬁcation in an interactive theorem
prover like Coq would be extremely difﬁcult and tedious.
On the other hand, proving liveness also needs some extra
assumptions about the system, for example, the block interval
should be long enough for the messages to propagate.

Nevertheless, some of the assumptions of our model can
be weakened to better approximate the actual situation. For
instance, in practice hash function is not perfectly collision-
resistent, we can weaken our assumption about hash function
and consider detecting hash collision when receiving blocks
and requesting transactions. Also, it is possible to consider
certain type of Byzantine faults in the model and verify that
the consensus protocol is resistent to the certain type of fault.
This would be a more realistic model and could provide a
stronger guarantee of the safety of the system.

V. RELATED WORK

In this section, we present a brief review of the latest

advances in ensuring security of blockchain.

A. Consistency of Blockchain Protocols.

When the ﬁrst blockchain Bitcoin was proposed, Satoshi
Nakamoto proved that the blockchain cannot be altered in a
probabilistic sense as long as honest nodes collectively control
more computing power than attacker nodes [1]. [16] estab-
lished two properties about Bitcoin in a synchronous setting,
called Common preﬁx and Chain quality. [17] provided prob-
abilistic boundaries with respect to chain growth and quality
in an asynchronous environment, other properties like liveness
were also analyzed in the work. Bitcoin’s consensus protocol
is based on the proof-of-work mechanism, another mechanism
called proof-of-stake was proposed [18], [19]. [20] and [21]
provided two proof-of-stake based blockchains with rigorous
security guarantees called Snow White and Ouroboros. These
works mainly focused on probabilistic reasoning about a
protocol modeled as a composition of distributions.

B. Formal Veriﬁcation of Blockchain.

Unlike the above works based on probabilistic reasoning,
the use of formal veriﬁcation techniques to validate the
blockchain and its applications can provide complete assur-
ance. [22] proposed a model checking based approach to semi-
automatically verify the consensus algorithms in asynchronous
environment. [23]–[25] used different model checkers to verify
properties of blockchain and smart contracts. [26] combined
theorem proving and testing for analysis of Ethereum Virtual
Machine (EVM) and smart contracts. Algorand [11] consensus
protocol and smart contracts were modeled using the theorem
prover Coq in [10] and [27], and [10] also proved that
blockchain in Algorand never forks as long as the majority
is honest under certain assumptions. [28] and [29] presented
formal veriﬁcation of the CKB block synchronization proto-
col using model checking and theorem proving techniques
respectively. The CKB consensus protocol was formalized
as timed automata in [30], where several safety properties
were also veriﬁed through model checking, but the quiescent
consensus property was not included, nor was the operational
semantics given. In [12] the authors mechanized proof-of-work
consensus protocol and proved eventual consensus in clique
asynchronous network using Coq. This framework applies
to most Bitcoin-like proof-of-work consensus protocol, but

Authorized licensed use limited to: Institute of Information EngineeringCAS. Downloaded on December 08,2024 at 08:14:19 UTC from IEEE Xplore.  Restrictions apply.

666

not the CKB consensus protocol due to the novelty of CKB
blockchain.

VI. CONCLUSION

In this paper, we focus on providing a formal model of CKB
consensus protocol in Coq and verifying the quiescent consis-
tency property. Fundamental components of CKB consensus
protocol are modeled, including the special block structure,
the two-step conﬁrmation mechanism, and the peer-to-peer
network. The CKB network system is modeled as a transition
system. The operational semantics of the system are given, and
we establish the quiescent consistency property of the CKB
consensus protocol, i.e. all nodes agree on the same ledger
when there are no inﬂight messages. Such property is obtained
by proving a stronger invariant we call consensus invariant.
These formally veriﬁed properties provide guarantees of the
safety of CKB blockchain under certain assumptions.

In the future, we are going to reﬁne our model to verify
other properties of CKB consensus protocol, such as live-
ness, selﬁsh-mining-resistance, and quiescent consistency un-
der weaker assumptions. We also plan to extend our framework
towards veriﬁed smart contracts.

ACKNOWLEDGMENTS

This work was partially supported by the National Natu-
ral Science Foundation of China under grant no. 62172019,
61772038 and the Guangdong Science and Technology De-
partment (Grant no. 2018B010107004).

REFERENCES

[1] S. Nakamoto, “Bitcoin: A peer-to-peer electronic cash system,” 2008.

[Online]. Available: http://www.bitcoin.org/bitcoin.pdf

[2] G. Wood, “Ethereum: A secure decentralised generalised transaction

ledger,” Ethereum Yellow Paper, 2014.

[3] L. Ante, “Smart contracts on the blockchain – a bibliometric analysis
and review,” Telematics and Informatics, vol. 57, p. 101519, 2021.
[4] J. R. Varma, “Blockchain in ﬁnance,” Vikalpa, vol. 44, no. 1, pp. 1–11,

2019.

[5] M. Hölbl, M. Kompara, A. Kamišali´c, and L. Nemec Zlatolas, “A
systematic review of the use of blockchain in healthcare,” Symmetry,
vol. 10, no. 10, 2018.

[6] N. Popper, “A hacking of more than $50 million dashes hopes in the
world of virtual currency,” The New York Times, 2016. [Online].
Available: https://www.nytimes.com/2016/06/18/business/dealbook/
hacker- may- have- removed- more- than- 50- million- from- experimental-
cybercurrency-project.html

[7] “Nervos network homepage,” accessed: 2021-05-13. [Online]. Available:

https://www.nervos.org

[8] I. Eyal and E. G. Sirer, “Majority is not enough: Bitcoin mining is
vulnerable,” Commun. ACM, vol. 61, no. 7, p. 95–102, Jun. 2018.
[9] R. Zhang, “CKB consensus protocol,” accessed: 2021-05-13. [Online].
Available: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0020-
ckb-consensus-protocol

[10] M. A. Alturki, J. Chen, V. Luchangco, B. M. Moore, K. Palmskog,
L. Peña, and G. Rosu, “Towards a veriﬁed model of the Algorand
consensus protocol in Coq,” CoRR, vol. abs/1907.05523, 2019. [Online].
Available: http://arxiv.org/abs/1907.05523

[11] J. Chen and S. Micali, “Algorand: A secure and efﬁcient distributed

ledger,” Theoretical Computer Science, vol. 777, pp. 155–183, 2019.

[12] G. Pîrlea and I. Sergey, “Mechanising blockchain consensus,” in Pro-
ceedings of the 7th ACM SIGPLAN International Conference on Cer-
tiﬁed Programs and Proofs, ser. CPP 2018. New York, NY, USA:
Association for Computing Machinery, 2018, p. 78–90.

[13] “Coq proof assistant,” accessed: 2021-05-13.

[Online]. Available:

http://coq.inria.fr

[14] S. Burckhardt, A. Gotsman, H. Yang, and M. Zawirski, “Replicated
data types: Speciﬁcation, veriﬁcation, optimality,” in POPL 2014: 41st
ACM SIGPLAN-SIGACT Symposium on Principles of Programming
Languages. San Diego, CA, United States: ACM, Jan. 2014, pp. 271–
284.

[15] X. Luan and M. Sun, “CKB veriﬁcation,” 2021. [Online]. Available:

https://github.com/luan-xiaokun/ckb-veriﬁcation

[16] J. Garay, A. Kiayias, and N. Leonardos, “The Bitcoin backbone protocol:
Analysis and applications,” in Advances in Cryptology - EUROCRYPT
2015, E. Oswald and M. Fischlin, Eds. Berlin, Heidelberg: Springer
Berlin Heidelberg, 2015, pp. 281–310.

[17] R. Pass, L. Seeman, and A. Shelat, “Analysis of the blockchain protocol
in asynchronous networks,” in Advances in Cryptology – EUROCRYPT
2017, J.-S. Coron and J. B. Nielsen, Eds. Cham: Springer International
Publishing, 2017, pp. 643–673.

[18] I. Bentov, A. Gabizon, and A. Mizrahi, “Cryptocurrencies without
proof of work,” CoRR, vol. abs/1406.5694, 2014. [Online]. Available:
http://arxiv.org/abs/1406.5694

[19] S. King and S. Nadal, “Ppcoin: Peer-to-peer crypto-currency with
[Online]. Available:

proof-of-stake,” 2012, accessed: 2021-05-13.
https://www.peercoin.net/whitepapers/peercoin-paper.pdf

[20] P. Daian, R. Pass, and E. Shi, “Snow White: Robustly reconﬁgurable
consensus and applications to provably secure proof of stake,” in
Financial Cryptography and Data Security, I. Goldberg and T. Moore,
Eds. Cham: Springer International Publishing, 2019, pp. 23–41.
[21] A. Kiayias, A. Russell, B. David, and R. Oliynykov, “Ouroboros: A
provably secure proof-of-stake blockchain protocol,” in Advances in
Cryptology – CRYPTO 2017, J. Katz and H. Shacham, Eds. Cham:
Springer International Publishing, 2017, pp. 357–388.

[22] T. Tsuchiya and A. Schiper, “Veriﬁcation of consensus algorithms
using satisﬁability solving,” Distributed Computing, vol. 23, no. 5-6,
p. 341–358, 2011.

[23] G. Bigi, A. Bracciali, G. Meacci, and E. Tuosto, “Validation of decen-
tralised smart contracts through game theory and formal methods,” in
Programming Languages with Applications to Biology and Security -
Essays Dedicated to Pierpaolo Degano on the Occasion of His 65th
Birthday, ser. Lecture Notes in Computer Science, C. Bodei, G. L.
Ferrari, and C. Priami, Eds., vol. 9465. Springer, 2015, pp. 142–161.
[24] K. Chaudhary, A. Fehnker, J. van de Pol, and M. Stoelinga, “Modeling
and veriﬁcation of the Bitcoin protocol,” in Proceedings Workshop on
Models for Formal Analysis of Real Systems, MARS 2015, Suva, Fiji,
November 23, 2015, ser. EPTCS, R. J. van Glabbeek, J. F. Groote, and
P. Höfner, Eds., vol. 196, 2015, pp. 46–60.

[25] X. Bai, Z. Cheng, Z. Duan, and K. Hu, “Formal modeling and veriﬁ-
cation of smart contracts,” in Proceedings of the 2018 7th International
Conference on Software and Computer Applications, ser. ICSCA 2018.
New York, NY, USA: Association for Computing Machinery, 2018, p.
322–326.

[26] X. Zhang, Y. Li, and M. Sun, “Towards a formally veriﬁed EVM
in production environment,” in Coordination Models and Languages,
S. Bliudze and L. Bocchi, Eds. Cham: Springer International Publish-
ing, 2020, pp. 341–349.

[27] M. Bartoletti, A. Bracciali, C. Lepore, A. Scalas, and R. Zunino, “A
formal model of Algorand smart contracts,” CoRR, vol. abs/2009.12140,
2020. [Online]. Available: https://arxiv.org/abs/2009.12140

[28] Q. Zhang, Y. Lu, and M. Sun, “Modeling and veriﬁcation of the Nervos
CKB block synchronization protocol in UPPAAL,” in Blockchain and
Trustworthy Systems - Second International Conference, BlockSys 2020,
Dali, China, August 6-7, 2020, Revised Selected Papers, ser. Communi-
cations in Computer and Information Science, Z. Zheng, H. Dai, X. Fu,
and B. Chen, Eds., vol. 1267. Springer, 2020, pp. 3–17.

[29] H. Bu and M. Sun, “Towards modeling and veriﬁcation of the CKB
block synchronization protocol in Coq,” in Formal Methods and Soft-
ware Engineering, S.-W. Lin, Z. Hou, and B. Mahony, Eds. Cham:
Springer International Publishing, 2020, pp. 287–296.

[30] Y.-C. Feng, Y. Lu, and M. Sun, “Modeling and veriﬁcation of CKB con-
sensus protocol in UPPAAL,” in Proceedings of the 33rd International
Conference on Software Engineering and Knowledge Engineering. KSI
Research Inc. and Knowledge Systems Institute Graduate School, 2021,
pp. 150–153.

Authorized licensed use limited to: Institute of Information EngineeringCAS. Downloaded on December 08,2024 at 08:14:19 UTC from IEEE Xplore.  Restrictions apply.

667


