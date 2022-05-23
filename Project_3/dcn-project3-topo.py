from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts
        host1 = self.addHost( 'h1' )
        host2 = self.addHost( 'h2' )
        host3 = self.addHost( 'h3' )
        host4 = self.addHost( 'h4' )
        host5 = self.addHost( 'h5' )
        host6 = self.addHost( 'h6' )

        # Add switches
        sw1 = self.addSwitch( 's1' )
        sw2 = self.addSwitch( 's2' )
        sw3 = self.addSwitch( 's3' )
        sw4 = self.addSwitch( 's4' )

        # Add links between switches
        self.addLink( sw1, sw2, bw=1000, loss=5 )
        self.addLink( sw2, sw3, bw=1000, loss=5 )
        self.addLink( sw3, sw4, bw=1000, loss=5 )

        # Add link between host and switches
        self.addLink( host1, sw1, bw=100, loss=0 )
        self.addLink( host2, sw1, bw=100, loss=0 )
        self.addLink( host3, sw2, bw=100, loss=0 )
        self.addLink( host4, sw3, bw=100, loss=0 )
        self.addLink( host5, sw4, bw=100, loss=0 )
        self.addLink( host6, sw4, bw=100, loss=0 )



topos = { 'mytopo': ( lambda: MyTopo() ) }