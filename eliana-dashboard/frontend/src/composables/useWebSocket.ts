// useWebSocket：WebSocket 連線與自動重連邏輯
import { ref, type Ref } from 'vue'
import type { ConnectionStatus, DashboardMessage } from '../types/dashboard'

export const RECONNECT_INTERVAL = 5000 // 5 秒

export interface UseWebSocketOptions {
  url: string
  onMessage?: (msg: DashboardMessage) => void
  // 注入式 WebSocket 建構子（測試可替換為 mock）
  socketFactory?: (url: string) => WebSocket
  reconnectInterval?: number
}

export interface UseWebSocketReturn {
  status: Ref<ConnectionStatus>
  connect: () => void
  disconnect: () => void
  isConnected: () => boolean
}

export function useWebSocket(options: UseWebSocketOptions): UseWebSocketReturn {
  const status = ref<ConnectionStatus>('disconnected')
  const interval = options.reconnectInterval ?? RECONNECT_INTERVAL
  const factory = options.socketFactory ?? ((url: string) => new WebSocket(url))

  let socket: WebSocket | null = null
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  let manualClose = false

  function clearTimer() {
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
  }

  function scheduleReconnect() {
    if (manualClose) return
    status.value = 'reconnecting'
    clearTimer()
    reconnectTimer = setTimeout(() => {
      connect()
    }, interval)
  }

  function connect() {
    manualClose = false
    clearTimer()
    try {
      socket = factory(options.url)
    } catch {
      scheduleReconnect()
      return
    }

    socket.onopen = () => {
      status.value = 'connected'
    }
    socket.onmessage = (event: MessageEvent) => {
      try {
        const msg = JSON.parse(event.data) as DashboardMessage
        options.onMessage?.(msg)
      } catch {
        // 忽略無法解析的訊息
      }
    }
    socket.onclose = () => {
      if (!manualClose) {
        scheduleReconnect()
      } else {
        status.value = 'disconnected'
      }
    }
    socket.onerror = () => {
      // 錯誤後由 onclose 觸發重連
      socket?.close()
    }
  }

  function disconnect() {
    manualClose = true
    clearTimer()
    if (socket) {
      socket.close()
      socket = null
    }
    status.value = 'disconnected'
  }

  function isConnected(): boolean {
    return status.value === 'connected'
  }

  return { status, connect, disconnect, isConnected }
}
