require 'socket'
require 'logger'
require 'ipaddr'
require 'json'

require 'roda'

Thread.abort_on_exception = true

# daemon to sit and listen on UDP 10000 for Orvibo socket messages
# and also TCP 10000 for commands

module Rack
  class CommonLogger
    def log(env, status, header, began_at)
      # make rack STFU
    end
  end
end

class Orvibo
  class Socket
    attr_accessor :mac, :on, :ip
    attr_accessor :subscribed_at, :changed_at
  end

  TWENTIES     = [0x20, 0x20, 0x20, 0x20, 0x20, 0x20].pack('C*')

  DIS_PREAMBLE = [0x68, 0x64, 0x00, 0x06, 0x71, 0x61].pack('C*')
  DISCOVER     = [0x68, 0x64, 0x00, 0x2A, 0x71, 0x61].pack('C*')

  FIND_PREAMBLE = [0x68, 0x64, 0x00, 0x12, 0x71, 0x67].pack('C*')
  FIND         = [0x68, 0x64, 0x00, 0x2A, 0x71, 0x67].pack('C*')

  FBK_PREAMBLE = [0x68, 0x64, 0x00, 0x1e, 0x63, 0x6c].pack('C*')
  SUBSCRIBED   = [0x68, 0x64, 0x00, 0x18, 0x63, 0x6c].pack('C*')

  CTL_PREAMBLE = [0x68, 0x64, 0x00, 0x17, 0x64, 0x63].pack('C*')
  ONOFF        = [0x68, 0x64, 0x00, 0x17, 0x73, 0x66].pack('C*')
  CTL_ON       = [0x00, 0x00, 0x00, 0x00, 0x01].pack('C*')
  CTL_OFF      = [0x00, 0x00, 0x00, 0x00, 0x00].pack('C*')

  attr_reader :sockets
  attr_reader :udp
  private :udp

  def initialize
    # hash of known sockets and their status fields
    @sockets = {}

    @logger = Logger.new(STDERR)

    @udp = UDPSocket.new
    @udp.setsockopt(:SOL_SOCKET, :SO_BROADCAST, true)
    @udp.setsockopt(:SOL_SOCKET, :SO_REUSEADDR, true)
    @udp.bind(0, 10_000) # Socket::INADDR_ANY
  end

  def ctl(mac, on)
    return unless (socket = sockets[mac])

    action = CTL_PREAMBLE + socket.mac + TWENTIES + (on ? CTL_ON : CTL_OFF)
    udp.send(action, 0, socket.ip, 10_000)
    socket.changed_at = Time.now
  end

  def listen
    loop do
      packet, sender = udp.recvfrom(1024)
      _family, _port, ip = sender

      # debug, ignore all but the given IP
      # next if ip != '192.168.0.208'

      # what sort of packet is it?
      case packet[0, 6]
      when DISCOVER
        type = :discover
        mac = packet[7, 6]
      when FIND
        type = :find
        mac = packet[7, 6]
      when SUBSCRIBED
        type = :subscribed
        mac = packet[6, 6]
      when CTL_PREAMBLE
        type = :ctl_preamble
        mac = packet[6, 6]
      when ONOFF
        type = :ctl
        mac = packet[6, 6]
      else
        s = packet.unpack('C*').map { |c| c.to_s(16) }.join(' ')
        @logger.warn "#{ip} UNHANDLED: " + s
        next
      end

      on = packet[-1].unpack('C').first == 1
      mac_readable = mac.unpack('C*').map { |c| c.to_s(16) }.join(':')

      # @logger.debug "#{mac_readable} #{ip} #{type} on=#{on}"

      unless (orvibo = sockets[mac_readable])
        # new socket setup
        orvibo = sockets[mac_readable] = Orvibo::Socket.new
        orvibo.mac = mac
        orvibo.subscribed_at = Time.now - 300
        orvibo.changed_at = Time.now
      end

      orvibo.ip = ip # just in case it's moved.
      if orvibo.on != on
        orvibo.on = on
        @logger.info "#{mac_readable} is now #{on ? 'on' : 'off'}"
      end

      # special packet processing
      case type
      when :subscribed
        orvibo.subscribed_at = Time.now
      end

      # time to renew subscription?
      next unless Time.now - orvibo.subscribed_at > 120
      # send subscription
      subscribe = FBK_PREAMBLE + orvibo.mac + TWENTIES +
                  orvibo.mac.reverse + TWENTIES
      udp.send subscribe, 0, orvibo.ip, 10_000
      # orvibo.subscribed_at is set when the socket acknowledges
    end
  end
end

$orvibod = Orvibo.new

# Orvibo daemon listening thread
Thread.new { $orvibod.listen }

class WebApp < Roda
  plugin :halt
  plugin :json
  plugin :json_parser

  route do |r|
    r.get 'list' do
      $orvibod.sockets.map { |k, v| [k, v.on ? 'on' : 'off'] }.to_h
    end

    r.get 'status' do
      mac = r.params['mac']
      r.halt 404 unless $orvibod.sockets[mac]
      { mac => $orvibod.sockets[mac].on ? 'on' : 'off' }
    end

    r.post 'ctl' do
      mac, ctl = r.params.values_at('mac', 'ctl')
      r.halt 404 unless $orvibod.sockets[mac]
      $orvibod.ctl(mac, ctl == 'on')
    end

    r.root do
      $orvibod.sockets.map { |k, v| "#{k} is #{v.on ? 'on' : 'off'}" }
              .join('<br>')
    end
  end
end
