document.addEventListener('DOMContentLoaded', () => {
  const loginAttemptsTableBody = document.getElementById('loginAttemptsTableBody');
  const unauthorizedAccessTableBody = document.getElementById('unauthorizedAccessTableBody');
  const authenticationTransactionsTableBody = document.getElementById('authenticationTransactionsTableBody');
  const ddosLogsTableBody = document.getElementById('ddosLogsTableBody');
  const requestLogsTableBody = document.getElementById('requestLogsTableBody');
  
  const sendEncryptedBtn = document.getElementById('sendEncryptedBtn');
  const encryptedMessageStatus = document.getElementById('encryptedMessageStatus');

  // Fetch logs function
  async function fetchLogs(url, tableBody, transformFunc) {
    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error('Failed to fetch logs');
      }
      const data = await response.json();
      const transformedData = transformFunc(data);

      tableBody.innerHTML = '';
      transformedData.forEach(item => {
        const row = document.createElement('tr');
        for (let key in item) {
          const cell = document.createElement('td');
          cell.innerText = item[key];
          row.appendChild(cell);
        }
        tableBody.appendChild(row);
      });
    } catch (error) {
      console.error('Error fetching logs:', error);
      encryptedMessageStatus.innerText = `Error fetching logs: ${error.message}`;
    }
  }

  // Transform function for login attempts
  function transformLoginAttempts(data) {
    return data.map(entry => ({
      timestamp: entry.timestamp || 'N/A',
      ip: entry.ip || 'N/A',
      username: entry.username || 'N/A',
      sqli: entry.sqli || 'N/A'
    }));
  }

  // Transform function for unauthorized access
  function transformUnauthorizedAccess(data) {
    return data.map(entry => ({
      timestamp: entry.timestamp || 'N/A',
      ip: entry.ip || 'N/A',
      username: entry.username || 'N/A'
    }));
  }

  // Transform function for authentication transactions
  function transformAuthenticationTransactions(data) {
    return data.map(entry => ({
      timestamp: entry.timestamp || 'N/A',
      status: entry.status || 'N/A',
      message: entry.message || 'N/A'
    }));
  }

  // Transform function for DDoS logs
  function transformDdosLogs(data) {
    return data.map(entry => ({
      timestamp: entry.timestamp || 'N/A',
      sender_ip: entry.sender_ip || 'N/A',
      receiver_ip: entry.receiver_ip || 'N/A',
      ua: entry.ua || 'N/A',            // Ensure 'ua' key matches the returned field
      url: entry.url || 'N/A',          // Ensure 'url' key matches the returned field
      status: entry.status || 'N/A'     // Ensure 'status' key matches the returned field
    }));
  }

  // Transform function for request logs
  function transformRequestLogs(data) {
    return data.map(entry => ({
      timestamp: entry.timestamp || 'N/A',
      sender_ip: entry.sender_ip || 'N/A',
      receiver_ip: entry.receiver_ip || 'N/A',
      url: entry.url || 'N/A',
      method: entry.method || 'N/A',
      ua: entry.ua || 'N/A',
      status: entry.status || 'N/A'
    }));
  }

  // Fetch and display all logs when the page is loaded
  fetchLogs('/api/login-attempts', loginAttemptsTableBody, transformLoginAttempts);
  fetchLogs('/api/unauthorized-access', unauthorizedAccessTableBody, transformUnauthorizedAccess);
  fetchLogs('/api/authentication-transactions', authenticationTransactionsTableBody, transformAuthenticationTransactions);
  fetchLogs('/api/ddos-logs', ddosLogsTableBody, transformDdosLogs);
  fetchLogs('/api/request-logs', requestLogsTableBody, transformRequestLogs);

  // Event listener for sending encrypted message
  sendEncryptedBtn.addEventListener('click', async () => {
    encryptedMessageStatus.innerText = 'Sending encrypted message...';
    try {
      const response = await fetch('/send_to_auth_server');
      const result = await response.json();
      if (response.ok) {
        encryptedMessageStatus.innerText = `Server Response: ${JSON.stringify(result.auth_server_response)}`;
      } else {
        encryptedMessageStatus.innerText = `Error: ${result.error}`;
      }
    } catch (error) {
      encryptedMessageStatus.innerText = `Failed to send encrypted message: ${error.message}`;
      console.error('Encrypted message error:', error);
    }
  });
});
