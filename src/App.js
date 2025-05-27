import React, { useState, useEffect, useRef, useCallback } from 'react';
import io from 'socket.io-client';
import axios from 'axios';
import './App.css';
import { IoSearchOutline, IoSettingsOutline, IoSendSharp, IoAttachOutline, IoChevronBack, IoMenu } from 'react-icons/io5';
import { BsChatLeft, BsInfoCircle } from 'react-icons/bs';
import { FiUser } from 'react-icons/fi';

// API and backend URLs
const apiBase = process.env.REACT_APP_API_BASE || 'https://convodb1.onrender.com/api';
const backendUrl = process.env.REACT_APP_BACKEND_URL || 'https://convodb1.onrender.com';

// Axios instance
const api = axios.create({
  baseURL: apiBase,
  withCredentials: true,
});

// Socket.IO connection
const socket = io(backendUrl, {
  withCredentials: true,
  transports: ['websocket', 'polling'],
});

// Sidebar Component
const Sidebar = ({ username, users, searchTerm, setSearchTerm, recipient, setRecipient, loadChatHistory, unreadMessages, userDPs, isSidebarOpen, toggleSidebar, onlineUsers }) => {
  return (
    <div className={`sidebar ${isSidebarOpen ? 'open' : ''}`}>
      <div className="sidebar-header">
        <div className="header-top">
          <h1>Convo</h1>
          <button className="sidebar-toggle" onClick={() => toggleSidebar(false)}>
            <IoChevronBack size={24} />
          </button>
        </div>
        <div className="search-input-container">
          <input
            type="text"
            placeholder="Search users..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input-text"
          />
          <IoSearchOutline className="search-icon" />
        </div>
      </div>
      <div className="contacts">
        <h2>Contacts</h2>
        {users.length > 0 ? (
          users.map((user) => (
            <div
              key={user}
              className={`user-item ${user === recipient ? 'active' : ''}`}
              onClick={() => {
                setRecipient(user);
                loadChatHistory(username, user);
                toggleSidebar(false);
                setSearchTerm('');
              }}
            >
              {userDPs[user] ? (
                <img src={`${backendUrl}/Uploads/${userDPs[user]}`} alt={user} className="user-avatar" />
              ) : (
                <div className="user-avatar-placeholder">{user.charAt(0).toUpperCase()}</div>
              )}
              <span className="user-name">{user}</span>
              {unreadMessages[user] > 0 && (
                <span className="message-count">{unreadMessages[user]}</span>
              )}
              <small>{onlineUsers.includes(user) ? 'Online' : 'Offline'}</small>
            </div>
          ))
        ) : (
          <p className="no-results">No contacts available. Start a conversation!</p>
        )}
      </div>
    </div>
  );
};

// ChatHeader Component
const ChatHeader = ({ recipient, userDPs, setIsSettingsOpen, toggleSidebar, onlineUsers }) => {
  return (
    <div className="chat-header">
      <div className="user-info">
        <IoMenu className="menu-button" onClick={() => toggleSidebar(true)} />
        {recipient && (
          <>
            {userDPs[recipient] ? (
              <img src={`${backendUrl}/Uploads/${userDPs[recipient]}`} alt={recipient} className="profile-pic" />
            ) : (
              <div className="profile-pic-placeholder">{recipient.charAt(0).toUpperCase()}</div>
            )}
            <div>
              <div>{recipient}</div>
              <small>{onlineUsers.includes(recipient) ? 'Online' : 'Offline'}</small>
            </div>
          </>
        )}
      </div>
      <button onClick={() => setIsSettingsOpen(true)} className="settings-button">
        <IoSettingsOutline size={20} />
      </button>
    </div>
  );
};

// UserProfile Component
const UserProfile = ({ username, profilePic, setView }) => {
  return (
    <div className="user-profile">
      <IoChevronBack className="close-button" onClick={() => setView('chat')} />
      <div className="profile-info">
        <img
          src={profilePic ? `${backendUrl}/Uploads/${profilePic}` : `https://placehold.co/120?text=${username.charAt(0)}`}
          alt={username}
          className="profile-pic-large"
        />
        <h2>{username}</h2>
        <p>Status: Online</p>
      </div>
    </div>
  );
};

// InfoPage Component
const InfoPage = ({ setView }) => {
  return (
    <div className="info-page">
      <IoChevronBack className="close-button" onClick={() => setView('chat')} />
      <div className="info-content">
        <h2>Welcome to Convo</h2>
        <p>Convo is your space to connect with others! Here are some tips to get started:</p>
        <ul>
          <li>Search for friends using the search bar.</li>
          <li>Send messages or files by typing and attaching.</li>
          <li>Customize your profile in the settings.</li>
        </ul>
      </div>
    </div>
  );
};

// SettingsSidebar Component
const SettingsSidebar = ({ isSettingsOpen, setIsSettingsOpen, username, profilePic, handleLogout, updateProfilePic, profilePicInputRef }) => {
  return (
    <div className={`settings-sidebar ${isSettingsOpen ? 'open' : ''}`}>
      <div className="settings-header">
        <IoChevronBack onClick={() => setIsSettingsOpen(false)} className="close-button" />
        <h1>Settings</h1>
      </div>
      <div className="profile-section">
        <img
          src={profilePic ? `${backendUrl}/Uploads/${profilePic}` : `https://placehold.co/120?text=${username.charAt(0)}`}
          alt={username}
          className="profile-pic-large"
        />
        <span className="username-display">{username}</span>
        <input
          type="file"
          accept="image/*"
          onChange={updateProfilePic}
          className="profile-pic-input"
          id="profile-pic-upload"
          ref={profilePicInputRef}
        />
        <label htmlFor="profile-pic-upload" className="profile-pic-label">Change Picture</label>
        <div className="settings-options">
          <button onClick={handleLogout} className="logout-button">Logout</button>
        </div>
      </div>
    </div>
  );
};

// MessageInput Component
const MessageInput = ({ message, handleTyping, sendMessage, fileInputRef, sendFile }) => {
  return (
    <div className="input-container">
      <input
        type="text"
        value={message}
        onChange={handleTyping}
        onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
        className="message-input"
        placeholder="Type a message..."
      />
      <input
        type="file"
        accept="image/*,application/pdf"
        onChange={sendFile}
        className="file-input"
        id="file-upload"
        ref={fileInputRef}
      />
      <label htmlFor="file-upload" className="file-label">
        <IoAttachOutline size={22} />
      </label>
      <button onClick={sendMessage} className="send-button">
        <IoSendSharp size={18} />
      </button>
    </div>
  );
};

// Main App Component
function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState([]);
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [view, setView] = useState('login');
  const [recipient, setRecipient] = useState('');
  const [users, setUsers] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [error, setError] = useState('');
  const [typing, setTyping] = useState('');
  const [unreadMessages, setUnreadMessages] = useState({});
  const [profilePic, setProfilePic] = useState(null);
  const [userDPs, setUserDPs] = useState({});
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(window.innerWidth > 768);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const messageBoxRef = useRef(null);
  const fileInputRef = useRef(null);
  const profilePicInputRef = useRef(null);

  // Initialize authentication
  useEffect(() => {
    const token = localStorage.getItem('token');
    const storedUsername = localStorage.getItem('username');
    const urlParams = new URLSearchParams(window.location.search);
    const tokenParam = urlParams.get('token');
    const usernameParam = urlParams.get('username');
    const errorParam = urlParams.get('error');

    if (errorParam) {
      setError(`Authentication failed: ${errorParam}`);
      window.history.replaceState({}, document.title, '/');
      setTimeout(() => setError(''), 5000);
      return;
    }

    if (tokenParam && usernameParam) {
      localStorage.setItem('token', tokenParam);
      localStorage.setItem('username', decodeURIComponent(usernameParam));
      api.defaults.headers.common['Authorization'] = `Bearer ${tokenParam}`;
      setIsAuthenticated(true);
      setUsername(decodeURIComponent(usernameParam));
      socket.emit('registerUser', decodeURIComponent(usernameParam));
      fetchUsers();
      api
        .get(`/user/profile-pic/${decodeURIComponent(usernameParam)}`)
        .then((response) => setProfilePic(response.data.profilePic))
        .catch((err) => console.error('Failed to fetch profile pic:', err));
      setView('chat');
      window.history.replaceState({}, document.title, '/');
    } else if (token && storedUsername) {
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      setIsAuthenticated(true);
      setUsername(storedUsername);
      socket.emit('registerUser', storedUsername);
      fetchUsers();
      api
        .get(`/user/profile-pic/${storedUsername}`)
        .then((response) => setProfilePic(response.data.profilePic))
        .catch((err) => console.error('Failed to fetch profile pic:', err));
      setView('chat');
    }
  }, []);

  // Sidebar visibility
  useEffect(() => {
    const handleResize = () => {
      setIsSidebarOpen(window.innerWidth > 768);
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // Fetch users (simplified, like earlier)
  const fetchUsers = useCallback(async (query = '') => {
    if (!username || !isAuthenticated) return;
    try {
      const response = await api.get('/users/search', {
        params: { query, currentUser: username },
      });
      setUsers(response.data);
      const dpPromises = response.data.map((user) =>
        api
          .get(`/user/profile-pic/${user}`)
          .then((res) => ({ user, profilePic: res.data.profilePic }))
          .catch(() => ({ user, profilePic: null }))
      );
      const dps = await Promise.all(dpPromises);
      setUserDPs(Object.fromEntries(dps.map(({ user, profilePic }) => [user, profilePic])));
    } catch (error) {
      console.error('Fetch users error:', error);
      setError('Failed to load contacts');
      setTimeout(() => setError(''), 5000);
    }
  }, [username, isAuthenticated]);

  // Fetch users on search
  useEffect(() => {
    fetchUsers(searchTerm);
  }, [searchTerm, fetchUsers]);

  // Socket handling
  useEffect(() => {
    if (isAuthenticated) {
      socket.on('connect', () => console.log('Connected to server'));
      socket.on('receiveMessage', (msg) => {
        setMessages((prev) => [...prev, msg]);
        if (msg.username === recipient) {
          api.post(`/messages/mark-read/${username}/${msg.username}`);
        }
      });
      socket.on('userTyping', (data) => {
        if (data.username === recipient) {
          setTyping(data.username);
          setTimeout(() => setTyping(''), 2000);
        }
      });
      socket.on('userStatus', ({ user, status }) => {
        setOnlineUsers((prev) =>
          status === 'online' ? [...new Set([...prev, user])] : prev.filter((u) => u !== user)
        );
      });
      return () => {
        socket.off('receiveMessage');
        socket.off('userTyping');
        socket.off('userStatus');
      };
    }
  }, [isAuthenticated, username, recipient]);

  // Load chat history
  const loadChatHistory = async (currentUser, selectedRecipient) => {
    if (selectedRecipient) {
      try {
        const response = await api.get(`/messages/${currentUser}/${selectedRecipient}`);
        setMessages(
          response.data.map((msg) => ({
            messageId: msg.messageId,
            username: msg.sender,
            text: msg.text,
            timestamp: msg.timestamp,
            type: msg.type || 'text',
            file: msg.file || null,
          }))
        );
        await api.post(`/messages/mark-read/${currentUser}/${selectedRecipient}`);
      } catch (error) {
        console.error('Failed to fetch chat history:', error);
        setMessages([]);
      }
    } else {
      setMessages([]);
    }
  };

  // Google login
  const handleGoogleLogin = () => {
    window.location.href = `${backendUrl}/auth/google`;
  };

  // Register user
  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      await api.post('/auth/register', { email, username, password });
      setView('login');
      setError('');
    } catch (error) {
      setError(error.response?.data?.message || 'Registration failed');
    }
  };

  // Login user
  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await api.post('/auth/login', { email, password });
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('username', response.data.username);
      api.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`;
      setIsAuthenticated(true);
      setUsername(response.data.username);
      setView('chat');
      socket.emit('registerUser', response.data.username);
      fetchUsers();
      setError('');
    } catch (error) {
      setError(error.response?.data?.message || 'Login failed');
    }
  };

  // Send text message
  const sendMessage = async () => {
    if (message.trim() && isAuthenticated && recipient) {
      const msg = {
        username,
        text: message,
        timestamp: new Date().toISOString(),
        type: 'text',
      };
      try {
        const response = await api.post('/messages/sendText', {
          sender: username,
          recipient,
          text: message,
          timestamp: msg.timestamp,
        });
        socket.emit('sendMessage', {
          recipient,
          message: response.data.text,
          type: response.data.type,
          messageId: response.data.messageId,
          timestamp: response.data.timestamp,
          username,
        });
        setMessages((prev) => [...prev, response.data]);
        setMessage('');
        socket.emit('stopTyping', { recipient });
      } catch (error) {
        console.error('Failed to send message:', error);
        setError('Failed to send message');
        setTimeout(() => setError(''), 5000);
      }
    }
  };

  // Send file
  const sendFile = async (event) => {
    const file = event.target.files[0];
    if (file && isAuthenticated && recipient) {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('recipient', recipient);
      formData.append('username', username);
      formData.append('timestamp', new Date().toISOString());
      try {
        const response = await api.post('/messages/sendFile', formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
        });
        socket.emit('sendMessage', {
          recipient,
          message: null,
          type: response.data.type,
          file: response.data.file,
          messageId: response.data.messageId,
          timestamp: response.data.timestamp,
          username,
        });
        setMessages((prev) => [...prev, response.data]);
      } catch (error) {
        console.error('Failed to send file:', error);
        setError('Failed to send file');
        setTimeout(() => setError(''), 5000);
      }
      fileInputRef.current.value = '';
    }
  };

  // Update profile picture
  const updateProfilePic = async (event) => {
    const file = event.target.files[0];
    if (file && isAuthenticated) {
      const formData = new FormData();
      formData.append('profilePic', file);
      formData.append('username', username);
      try {
        const response = await api.post('/user/update-profile-pic', formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
        });
        setProfilePic(response.data.filename);
        setUserDPs((prev) => ({ ...prev, [username]: response.data.filename }));
      } catch (error) {
        console.error('Failed to update profile pic:', error);
        setError('Failed to update profile picture');
      }
      profilePicInputRef.current.value = '';
    }
  };

  // Handle typing
  const handleTyping = (e) => {
    setMessage(e.target.value);
    if (recipient && e.target.value) {
      socket.emit('typing', { recipient, username });
    } else {
      socket.emit('stopTyping', { recipient });
    }
  };

  // Scroll to bottom
  useEffect(() => {
    if (messageBoxRef.current) {
      messageBoxRef.current.scrollTop = messageBoxRef.current.scrollHeight;
    }
  }, [messages]);

  // Logout
  const handleLogout = () => {
    localStorage.clear();
    setIsAuthenticated(false);
    setUsername('');
    setMessages([]);
    setRecipient('');
    setView('login');
    setProfilePic(null);
    setUserDPs({});
    setIsSettingsOpen(false);
    socket.disconnect();
  };

  if (!isAuthenticated) {
    return (
      <div className="signup-container">
        <div className="signup-box">
          <h2>{view === 'login' ? 'Sign In' : 'Sign Up'}</h2>
          <div className="signup-nav">
            <button
              className={`nav ${view === 'login' ? 'active-tab' : ''}`}
              onClick={() => setView('login')}
            >
              Sign In
            </button>
            <button
              className={`nav ${view === 'register' ? 'active-tab' : ''}`}
              onClick={() => setView('register')}
            >
              Sign Up
            </button>
          </div>
          {error && <p className="error">{error}</p>}
          {view === 'login' ? (
            <form onSubmit={handleLogin}>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Email"
                className="signup-input"
                required
              />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
                className="signup-input"
                required
              />
              <button type="submit" className="signup-button">
                Sign In
              </button>
              <p className="already-have-account">
                Don't have an account?{' '}
                <a href="#" onClick={() => setView('register')}>
                  Sign Up
                </a>
              </p>
              <div className="or">OR</div>
              <button type="button" className="google-btn" onClick={handleGoogleLogin}>
                Sign In with Google
              </button>
            </form>
          ) : (
            <form onSubmit={handleRegister}>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username"
                className="signup-input"
                required
              />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Email"
                className="signup-input"
                required
              />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
                className="signup-input"
                required
              />
              <button type="submit" className="signup-button">
                Sign Up
              </button>
              <p className="have-account">
                Already have an account?{' '}
                <a href="#" onClick={() => setView('login')}>
                  Sign In
                </a>
              </p>
              <div className="or">OR</div>
              <button type="button" className="google-btn" onClick={handleGoogleLogin}>
                Sign Up with Google
              </button>
            </form>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="chat-container">
      {view === 'profile' && <UserProfile username={username} profilePic={profilePic} setView={setView} />}
      {view === 'info' && <InfoPage setView={setView} />}
      <div className="sidebar-icons">
        <div className="icon" onClick={() => { setView('chat'); setRecipient(''); setMessages([]); }}>
          <BsChatLeft size={20} />
        </div>
        <div className="icon" onClick={() => setView('profile')}>
          <FiUser size={20} />
        </div>
        <div className="icon" onClick={() => setView('info')}>
          <BsInfoCircle size={20} />
        </div>
        <img
          src={profilePic ? `${backendUrl}/Uploads/${profilePic}` : `https://placehold.co/40?text=${username.charAt(0)}`}
          alt={username}
          className="icon avatar"
        />
      </div>
      <Sidebar
        username={username}
        users={users}
        searchTerm={searchTerm}
        setSearchTerm={setSearchTerm}
        recipient={recipient}
        setRecipient={setRecipient}
        loadChatHistory={loadChatHistory}
        unreadMessages={unreadMessages}
        userDPs={userDPs}
        isSidebarOpen={isSidebarOpen}
        toggleSidebar={setIsSidebarOpen}
        onlineUsers={onlineUsers}
      />
      {view === 'chat' && (
        <div className="main-chat">
          <ChatHeader
            recipient={recipient}
            userDPs={userDPs}
            setIsSettingsOpen={setIsSettingsOpen}
            toggleSidebar={setIsSidebarOpen}
            onlineUsers={onlineUsers}
          />
          <div className="message-box" ref={messageBoxRef}>
            {!recipient ? (
              <p className="empty-convo">Convo<br />Connect with friends!</p>
            ) : messages.length === 0 ? (
              <p className="empty-convo">No messages yet. Say hi!</p>
            ) : (
              messages.map((msg, index) => (
                <div
                  key={msg.messageId || `message-${index}`}
                  className={msg.username === username ? 'sent-message-message' : 'received-message-message'}
                >
                  <div className={msg.username === username ? 'sent-message-text' : 'received-message-text'}>
                    {msg.type === 'text' ? (
                      <p>{msg.text}</p>
                    ) : (
                      <a
                        href={`${backendUrl}/Uploads/${msg.file}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="file-text"
                        download={msg.type === 'document'}
                      >
                        {msg.type === 'image' ? 'View Image' : 'Download Document'}
                      </a>
                    )}
                    <small>{new Date(msg.timestamp).toLocaleTimeString()}</small>
                  </div>
                </div>
              ))
            )}
            {typing && recipient && <p className="typing-indicator">{typing} is typing...</p>}
          </div>
          {recipient && (
            <MessageInput
              message={message}
              handleTyping={handleTyping}
              sendMessage={sendMessage}
              fileInputRef={fileInputRef}
              sendFile={sendFile}
            />
          )}
        </div>
      )}
      <SettingsSidebar
        isSettingsOpen={isSettingsOpen}
        setIsSettingsOpen={setIsSettingsOpen}
        username={username}
        profilePic={profilePic}
        handleLogout={handleLogout}
        updateProfilePic={updateProfilePic}
        profilePicInputRef={profilePicInputRef}
      />
    </div>
  );
}

export default App;