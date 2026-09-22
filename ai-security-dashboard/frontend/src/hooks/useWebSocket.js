import { useEffect, useState, useCallback, useRef } from 'react';

export const useWebSocket = (url) => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState(null);
  const [error, setError] = useState(null);
  const wsRef = useRef(null);

  useEffect(() => {
    const connectWebSocket = () => {
      try {
        const ws = new WebSocket(url);
        
        ws.onopen = () => {
          console.log('WebSocket connected');
          setIsConnected(true);
          setError(null);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            setLastMessage(data);
          } catch (e) {
            console.error('Failed to parse WebSocket message:', e);
          }
        };

        ws.onclose = () => {
          console.log('WebSocket disconnected');
          setIsConnected(false);
          // Attempt reconnection after 3 seconds
          setTimeout(connectWebSocket, 3000);
        };

        ws.onerror = (err) => {
          console.error('WebSocket error:', err);
          setError(err);
        };

        wsRef.current = ws;
      } catch (err) {
        console.error('Failed to create WebSocket:', err);
        setError(err);
      }
    };

    connectWebSocket();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [url]);

  const sendMessage = useCallback((message) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    }
  }, []);

  return { isConnected, lastMessage, error, sendMessage };
};

export default useWebSocket;
