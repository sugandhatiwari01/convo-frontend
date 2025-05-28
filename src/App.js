import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import io from 'socket.io-client';
import axios from 'axios';
import './App.css';
import { IoSearchOutline, IoSettingsOutline, IoSendSharp, IoAttachOutline, IoChevronBack, IoMenu } from 'react-icons/io5';
import { BsChatLeft, BsInfoCircle } from 'react-icons/bs';
import { FiUser } from 'react-icons/fi';
import { FaSpinner } from 'react-icons/fa';

// Error Boundary Component
class ErrorBoundary extends React.Component {
  state = { hasError: false, error: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('ErrorBoundary caught:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-container">
          <h1>Something went wrong</h1>
          <p>{this.state.error?.message || 'Please try refreshing the page.'}</p>
        </div>
      );
    }
    return this.props.children;
  }
}

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
  reconnection: true,
  reconnectionAttempts: 5,
  reconnectionDelay: 1000,
});

// Debounce utility
const debounce = (func, delay) => {
  let timeoutId;
  return (...args) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func.apply(null, args), delay);
  };
};

// Retry utility
const retry = async (fn, retries = 3, delay = 1000) => {
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (error) {
      if (i === retries - 1) throw error;
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
};

// Sidebar Component
const Sidebar = ({ username, users, searchTerm, setSearchTerm, recipient, setRecipient, loadChatHistory, unreadMessages, userDPs, isSidebarOpen, toggleSidebar, onlineUsers, showContactPicModal, isSearching }) => {
  const clearSearch = () => setSearchTerm('');

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
            placeholder={isSearching ? 'Searching...' : 'Search users (e.g., "s" or "su")...'}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
          <IoSearchOutline className="search-icon" />
          {searchTerm && (
            <button className="clear-search" onClick={clearSearch}>
              ×
            </button>
          )}
          {isSearching && <FaSpinner className="spinner" />}
        </div>
      </div>
      <div className="recents">
        <h2>Recents</h2>
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
                <img
                  src={`${backendUrl}/Uploads/${userDPs[user]}`}
                  alt={user}
                  className="user-avatar"
                  onClick={(e) => {
                    e.stopPropagation();
                    showContactPicModal(user, `${backendUrl}/Uploads/${userDPs[user]}`);
                  }}
                  style={{ cursor: 'pointer' }}
                />
              ) : (
                <div
                  className="user-avatar-placeholder"
                  onClick={(e) => {
                    e.stopPropagation();
                    showContactPicModal(user, null);
                  }}
                  style={{ cursor: 'pointer' }}
                >
                  {user.charAt(0).toUpperCase()}
                </div>
              )}
              <span className="user-name">
                {searchTerm && user.toLowerCase().includes(searchTerm.toLowerCase()) ? (
                  <>
                    {user.slice(0, user.toLowerCase().indexOf(searchTerm.toLowerCase()))}
                    <span className="highlight">
                      {user.slice(
                        user.toLowerCase().indexOf(searchTerm.toLowerCase()),
                        user.toLowerCase().indexOf(searchTerm.toLowerCase()) + searchTerm.length
                      )}
                    </span>
                    {user.slice(user.toLowerCase().indexOf(searchTerm.toLowerCase()) + searchTerm.length)}
                  </>
                ) : (
                  user
                )}
              </span>
              {unreadMessages[user] > 0 && (
                <span className="message-count">{unreadMessages[user]}</span>
              )}
              <small>{onlineUsers.includes(user) ? 'Online' : 'Offline'}</small>
            </div>
          ))
        ) : (
          <p>{searchTerm ? `No users found for "${searchTerm}"` : 'Type to search for contacts'}</p>
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
              <img
                src={`${backendUrl}/Uploads/${userDPs[recipient]}`}
                alt={recipient}
                className="profile-pic"
              />
            ) : (
              <div className="profile-pic-placeholder">
                {recipient.charAt(0).toUpperCase()}
              </div>
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

// Profile Picture Modal Component
const ProfilePicModal = ({ profilePic, username, onClose }) => {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose}>×</button>
        <img
          src={profilePic || `https://placehold.co/300?text=${username.charAt(0)}`}
          alt={username}
          className="modal-profile-pic"
        />
      </div>
    </div>
  );
};

// SettingsSidebar Component
const SettingsSidebar = ({ isSettingsOpen, setIsSettingsOpen, username, profilePic, handleLogout, updateProfilePic, profilePicInputRef, showProfilePicModal, theme, toggleTheme, showReactions, setShowReactions }) => {
  return (
    <div className={`settings-sidebar ${isSettingsOpen ? 'open' : ''}`}>
      <div className="settings-header">
        <IoChevronBack onClick={() => setIsSettingsOpen(false)} className="close-button" />
        <h1>Settings</h1>
      </div>
      <div className="settings-content">
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
        <label htmlFor="profile-pic-upload" className="profile-pic-label">Change Profile Picture</label>
        <div className="settings-options">
          <div className="option" onClick={showProfilePicModal}>View Profile Pic</div>
          <div className="option">
            Show Message Reactions
            <label className="reaction-toggle">
              <input
                type="checkbox"
                checked={showReactions}
                onChange={() => setShowReactions(!showReactions)}
              />
              <span className="reaction-toggle-slider"></span>
            </label>
          </div>
          <div className="option appearance-option">
            Appearance
            <div className="theme-toggle" onClick={toggleTheme}>
              <div className={`theme-toggle-slider ${theme === 'dark' ? 'checked' : ''}`}>
                <div className="theme-toggle-icon">
                  <div className="theme-icon-part sun"></div>
                  {[...Array(8)].map((_, i) => (
                    <div
                      key={i}
                      className="theme-icon-part ray"
                      style={{ transform: `rotate(${i * 45}deg) translateY(0.5em)` }}
                    ></div>
                  ))}
                </div>
              </div>
            </div>
          </div>
          <button onClick={handleLogout} className="logout-button">Log Out</button>
        </div>
      </div>
    </div>
  );
};

// MessageInput Component
const MessageInput = ({ message, handleTyping, sendMessage, fileInputRef, sendFile, isUploading }) => {
  return (
    <div className="input-container">
      <input
        type="text"
        value={message}
        onChange={handleTyping}
        onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
        className="message-input"
        placeholder="Enter Text..."
        disabled={isUploading}
      />
      <input
        type="file"
        accept="image/*,application/pdf"
        onChange={sendFile}
        className="file-input"
        id="file-upload"
        ref={fileInputRef}
        disabled={isUploading}
      />
      <label htmlFor="file-upload" className="file-label">
        <IoAttachOutline size={20} />
      </label>
      <button onClick={sendMessage} className="send-button" disabled={isUploading}>
        <IoSendSharp size={18} />
      </button>
      {isUploading && <FaSpinner className="spinner" />}
    </div>
  );
};

// Memoized Message Component
const Message = React.memo(({ msg, username, toggleReactionPicker, reactionPicker, handleReaction, showReactions, reactions }) => {
  return (
    <div className={msg.username === username ? 'sent-message-container' : 'received-message-container'}>
      {msg.type === 'text' ? (
        <div className={msg.username === username ? 'sent-message' : 'received-message'}>
          <p onClick={() => toggleReactionPicker(msg.messageId)} style={{ cursor: 'pointer' }}>
            {msg.text}
            <small>{new Date(msg.timestamp).toLocaleTimeString()}</small>
          </p>
          {reactionPicker.visible && reactionPicker.messageId === msg.messageId && (
            <div className="reaction-picker">
              {['👍', '❤️', '😂', '💪', '🔥'].map((emoji) => (
                <span
                  key={emoji}
                  className="reaction-emoji"
                  onClick={() => handleReaction(msg.messageId, emoji)}
                >
                  {emoji}
                </span>
              ))}
            </div>
          )}
          {showReactions && reactions[msg.messageId] && (
            <div className="reactions">
              {Object.entries(reactions[msg.messageId]).map(([user, emojis]) =>
                emojis.map((emoji, i) => (
                  <span key={`${user}-${emoji}-${i}`} className="reaction">
                    {emoji}
                  </span>
                ))
              )}
            </div>
          )}
        </div>
      ) : (
        <div className={msg.username === username ? 'sent-message' : 'received-message'}>
          {msg.file && (
            <a
              href={`${backendUrl}/Uploads/${msg.file}`}
              target="_blank"
              rel="noopener noreferrer"
              className="file-link"
              download={msg.type === 'document'}
            >
              {msg.type === 'image' ? 'View Image' : 'Download Document'}
            </a>
          )}
          <small>{new Date(msg.timestamp).toLocaleTimeString()}</small>
        </div>
      )}
    </div>
  );
});

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
  const [searchTerm, setSearchTerm] = useState(localStorage.getItem('searchTerm') || '');
  const [error, setError] = useState('');
  const [typing, setTyping] = useState('');
  const [unreadMessages, setUnreadMessages] = useState({});
  const [profilePic, setProfilePic] = useState(null);
  const [userDPs, setUserDPs] = useState({});
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(window.innerWidth > 768);
  const [isProfilePicModalOpen, setIsProfilePicModalOpen] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'light');
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [contactedUsernames, setContactedUsernames] = useState(JSON.parse(localStorage.getItem('contactedUsernames')) || []);
  const [contactModal, setContactModal] = useState({ isOpen: false, username: '', profilePic: null });
  const [reactions, setReactions] = useState(JSON.parse(localStorage.getItem('reactions')) || {});
  const [showReactions, setShowReactions] = useState(JSON.parse(localStorage.getItem('showReactions')) || true);
  const [reactionPicker, setReactionPicker] = useState({ messageId: null, visible: false });
  const [isSearching, setIsSearching] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const messageBoxRef = useRef(null);
  const fileInputRef = useRef(null);
  const profilePicInputRef = useRef(null);

  // Persist state in localStorage
  useEffect(() => {
    localStorage.setItem('contactedUsernames', JSON.stringify(contactedUsernames));
  }, [contactedUsernames]);

  useEffect(() => {
    localStorage.setItem('reactions', JSON.stringify(reactions));
  }, [reactions]);

  useEffect(() => {
    localStorage.setItem('showReactions', JSON.stringify(showReactions));
  }, [showReactions]);

  useEffect(() => {
    localStorage.setItem('searchTerm', searchTerm);
  }, [searchTerm]);

  // Apply theme
  useEffect(() => {
    document.body.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  }, [theme]);

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
      localStorage.setItem('username', decodeURIComponent(usernameParam).toLowerCase());
      api.defaults.headers.common['Authorization'] = `Bearer ${tokenParam}`;
      setIsAuthenticated(true);
      setUsername(decodeURIComponent(usernameParam).toLowerCase());
      socket.emit('registerUser', decodeURIComponent(usernameParam).toLowerCase());
      fetchUsers();
      fetchUnreadMessages();
      api
        .get(`/user/profile-pic/${decodeURIComponent(usernameParam).toLowerCase()}`)
        .then((response) => setProfilePic(response.data.profilePic))
        .catch((err) => console.error('Failed to fetch profile pic:', err.message));
      setView('chat');
      window.history.replaceState({}, document.title, '/');
    } else if (token && storedUsername) {
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      setIsAuthenticated(true);
      setUsername(storedUsername.toLowerCase());
      socket.emit('registerUser', storedUsername.toLowerCase());
      fetchUsers();
      fetchUnreadMessages();
      api
        .get(`/user/profile-pic/${storedUsername.toLowerCase()}`)
        .then((response) => setProfilePic(response.data.profilePic))
        .catch((err) => console.error('Failed to fetch profile pic:', err.message));
      setView('chat');
    } else {
      setView('login');
    }
  }, []);

  // Initialize sidebar visibility
  useEffect(() => {
    const handleResize = () => {
      setIsSidebarOpen(window.innerWidth > 768);
    };
    window.addEventListener('resize', handleResize);
    handleResize();
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // Toggle theme
  const toggleTheme = () => {
    setTheme((prevTheme) => (prevTheme === 'light' ? 'dark' : 'light'));
  };

  // Fetch unread messages
  const fetchUnreadMessages = useCallback(async () => {
    if (!username) return;
    try {
      const response = await retry(() => api.get(`/messages/unread/${username.toLowerCase()}`));
      setUnreadMessages(response.data);
    } catch (error) {
      console.error('Unread messages error:', error.message);
      setError('Failed to fetch unread messages');
      setTimeout(() => setError(''), 5000);
    }
  }, [username]);

  // Fetch users with optimized search
  const fetchUsers = useCallback(
    async (query = '') => {
      if (!username || !isAuthenticated) return;
      setIsSearching(true);
      try {
        const token = localStorage.getItem('token');
        if (!token) throw new Error('No authentication token');
        const response = await retry(() =>
          api.get('/users/search', {
            params: { query: query.toLowerCase(), currentUser: username.toLowerCase() },
            headers: { Authorization: `Bearer ${token}` },
          })
        );
        let uniqueUsers = [...new Set(response.data)].filter(
          (u) => u.toLowerCase() !== username.toLowerCase()
        );
        if (!query) {
          const recentUsers = uniqueUsers.filter((u) => contactedUsernames.includes(u));
          const otherUsers = uniqueUsers.filter((u) => !contactedUsernames.includes(u));
          uniqueUsers = [...recentUsers, ...otherUsers];
        }
        setUsers(uniqueUsers);
        const dpPromises = uniqueUsers.map((user) =>
          api
            .get(`/user/profile-pic/${user}`, { headers: { Authorization: `Bearer ${token}` } })
            .then((res) => ({ user, profilePic: res.data.profilePic }))
            .catch(() => ({ user, profilePic: null }))
        );
        const dps = await Promise.all(dpPromises);
        setUserDPs(Object.fromEntries(dps.map(({ user, profilePic }) => [user, profilePic])));
      } catch (error) {
        console.error('Fetch users error:', error.message);
        setError(`Failed to load contacts: ${error.message}`);
        setTimeout(() => setError(''), 5000);
        setUsers([...contactedUsernames].filter((u) => u.toLowerCase() !== username.toLowerCase()));
      } finally {
        setIsSearching(false);
      }
    },
    [username, isAuthenticated, contactedUsernames]
  );

  // Debounced fetch users
  const debouncedFetchUsers = useCallback(debounce(fetchUsers, 300), [fetchUsers]);

  // Search effect
  useEffect(() => {
    if (!searchTerm) {
      fetchUsers();
    } else {
      debouncedFetchUsers(searchTerm);
    }
  }, [searchTerm, fetchUsers]);

  // Memoized user list
  const filteredUsers = useMemo(() => {
    return users.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
  }, [users]);

  // Socket.IO handling
  useEffect(() => {
    if (isAuthenticated) {
      socket.on('connect', () => console.log('Connected to server'));
      socket.on('receiveMessage', (msg) => {
        setMessages((prev) => {
          if (!prev.some((m) => m.messageId === msg.messageId)) {
            return [...prev, msg];
          }
          return prev;
        });
        setContactedUsernames((prev) =>
          prev.includes(msg.username) ? prev : [...prev, msg.username]
        );
        if (msg.username === recipient) {
          setUnreadMessages((prev) => ({ ...prev, [msg.username]: 0 }));
          api.post(`/messages/mark-read/${username}/${msg.username}`);
        } else {
          setUnreadMessages((prev) => ({
            ...prev,
            [msg.username]: (prev[msg.username] || 0) + 1,
          }));
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
      socket.on('messagesRead', ({ recipient: readRecipient }) => {
        if (readRecipient === recipient.toLowerCase()) {
          setUnreadMessages((prev) => ({ ...prev, [readRecipient]: 0 }));
        }
      });
      return () => {
        socket.off('receiveMessage');
        socket.off('userTyping');
        socket.off('userStatus');
        socket.off('messagesRead');
      };
    }
  }, [isAuthenticated, username, recipient]);

  // Load chat history
  const loadChatHistory = async (currentUser, selectedRecipient) => {
    if (!selectedRecipient) {
      setMessages([]);
      return;
    }
    try {
      const response = await retry(() => api.get(`/messages/${currentUser.toLowerCase()}/${selectedRecipient.toLowerCase()}`));
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
      setUnreadMessages((prev) => ({ ...prev, [selectedRecipient]: 0 }));
      setContactedUsernames((prev) =>
        prev.includes(selectedRecipient) ? prev : [...prev, selectedRecipient]
      );
      await retry(() => api.post(`/messages/mark-read/${currentUser.toLowerCase()}/${selectedRecipient.toLowerCase()}`));
    } catch (error) {
      console.error('Failed to fetch chat history:', error.message);
      setMessages([]);
      setError('Failed to load messages');
      setTimeout(() => setError(''), 5000);
    }
  };

  // Google login
  const handleGoogleLogin = () => {
    const googleAuthUrl = `${backendUrl}/auth/google`;
    window.location.href = googleAuthUrl;
  };

  // Register user
  const handleRegister = async (e) => {
    e.preventDefault();
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      setError('Username must be 3-20 characters (letters, numbers, underscores)');
      setTimeout(() => setError(''), 5000);
      return;
    }
    if (!/^[\w-.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
      setError('Invalid email format');
      setTimeout(() => setError(''), 5000);
      return;
    }
    if (password.length < 6) {
      setError('Password must be at least 6 characters');
      setTimeout(() => setError(''), 5000);
      return;
    }
    try {
      await api.post('/api/users/register', { email, username: username.toLowerCase(), password });
      setView('login');
      setError('');
      setEmail('');
      setUsername('');
      setPassword('');
    } catch (error) {
      console.error('Registration error:', error.message);
      setError(error.response?.data?.message || 'Registration failed');
      setTimeout(() => setError(''), 5000);
    }
  };

  // Login user
  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await api.post('/api/users/login', { email, password });
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('username', response.data.username.toLowerCase());
      api.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`;
      setIsAuthenticated(true);
      setUsername(response.data.username.toLowerCase());
      setView('chat');
      socket.emit('registerUser', response.data.username.toLowerCase());
      fetchUsers();
      fetchUnreadMessages();
      setError('');
      setEmail('');
      setPassword('');
    } catch (error) {
      console.error('Login error:', error.message);
      setError(error.response?.data?.message || 'Login failed');
      setTimeout(() => setError(''), 5000);
    }
  };

  // Send text message
  const sendMessage = async () => {
    if (!message.trim() || !isAuthenticated || !recipient || isUploading) return;
    try {
      const response = await api.post('/api/messages/sendText', {
        sender: username.toLowerCase(),
        recipient: recipient.toLowerCase(),
        text: message,
        timestamp: new Date().toISOString(),
      });
      const savedMessage = response.data;
      setMessages((prev) =>
        prev.some((msg) => msg.messageId === savedMessage.messageId)
          ? prev
          : [...prev, savedMessage]
      );
      const emitWithRetry = (event, data, callback, retries = 3, delay = 1000) => {
        let attempts = 0;
        const tryEmit = () => {
          if (socket.connected) {
            socket.emit(event, data, callback);
          } else if (attempts < retries) {
            attempts++;
            setTimeout(tryEmit, delay);
          } else {
            setError('Failed to send message: No connection');
            setTimeout(() => setError(''), 5000);
          }
        };
        tryEmit();
      };
      emitWithRetry(
        'sendMessage',
        {
          recipient: recipient.toLowerCase(),
          message: savedMessage.text,
          type: savedMessage.type,
          messageId: savedMessage.messageId,
          timestamp: savedMessage.timestamp,
          username: username.toLowerCase(),
        },
        (response) => {
          if (response?.status === 'error') {
            setError(response.message || 'Failed to send message');
            setTimeout(() => setError(''), 5000);
          }
        }
      );
      setContactedUsernames((prev) =>
        prev.includes(recipient) ? prev : [...prev, recipient]
      );
      setMessage('');
      socket.emit('stopTyping', { recipient: recipient.toLowerCase() });
      await fetchUnreadMessages();
    } catch (error) {
      console.error('Send message error:', error.message);
      setError('Failed to send message');
      setTimeout(() => setError(''), 5000);
    }
  };

  // Send file
  const sendFile = async (event) => {
    const file = event.target.files[0];
    if (!file || !isAuthenticated || !recipient || isUploading) return;
    if (file.size > 5 * 1024 * 1024) {
      setError('File size must be less than 5MB');
      setTimeout(() => setError(''), 5000);
      return;
    }
    const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
    if (!allowedTypes.includes(file.type)) {
      setError('Only JPEG, PNG, and PDF files are allowed');
      setTimeout(() => setError(''), 5000);
      return;
    }
    setIsUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('recipient', recipient.toLowerCase());
      formData.append('username', username.toLowerCase());
      formData.append('timestamp', new Date().toISOString());
      const response = await api.post('/api/messages/uploadFile', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      const msg = response.data;
      setMessages((prev) =>
        prev.some((m) => m.messageId === msg.messageId) ? prev : [...prev, msg]
      );
      socket.emit('sendMessage', {
        recipient: recipient.toLowerCase(),
        type: msg.type,
        username: username.toLowerCase(),
        messageId: msg.messageId,
        file: msg.file,
        timestamp: msg.timestamp,
      });
      setContactedUsernames((prev) =>
        prev.includes(recipient) ? prev : [...prev, recipient]
      );
      await fetchUnreadMessages();
    } catch (error) {
      console.error('Failed to send file:', error.message);
      setError('Failed to send file');
      setTimeout(() => setError(''), 5000);
    } finally {
      setIsUploading(false);
      fileInputRef.current.value = '';
    }
  };

  // Update profile picture
  const updateProfilePic = async (event) => {
    const file = event.target.files[0];
    if (!file || !isAuthenticated || isUploading) return;
    setIsUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('username', username.toLowerCase());
      const response = await api.post('/api/users/uploadProfilePic', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setProfilePic(response.data.filename);
      setUserDPs((prev) => ({ ...prev, [username.toLowerCase()]: response.data.filename }));
    } catch (error) {
      console.error('Failed to update profile pic:', error.message);
      setError('Failed to update profile picture');
      setTimeout(() => setError(''), 5000);
    } finally {
      setIsUploading(false);
      profilePicInputRef.current.value = '';
    }
  };

  // Handle typing
  const handleTyping = (e) => {
    const value = e.target.value;
    setMessage(value);
    if (recipient && value) {
      socket.emit('typing', { recipient: recipient.toLowerCase(), username: username.toLowerCase() });
    } else {
      socket.emit('stopTyping', { recipient: recipient.toLowerCase() });
    }
  };

  // Handle reactions
  const handleReaction = (messageId, emoji) => {
    setReactions((prev) => {
      const messageReactions = prev[messageId] || {};
      const userReactions = messageReactions[username] || [];
      const updatedUserReactions = userReactions.includes(emoji)
        ? userReactions.filter((e) => e !== emoji)
        : [...userReactions, emoji];
      const updatedMessageReactions = {
        ...messageReactions,
        [username]: updatedUserReactions,
      };
      return { ...prev, [messageId]: updatedMessageReactions };
    });
    setReactionPicker({ messageId: null, visible: false });
  };

  // Toggle reaction picker
  const toggleReactionPicker = (messageId) => {
    setReactionPicker((prev) => ({
      messageId,
      visible: prev.messageId === messageId ? !prev.visible : true,
    }));
  };

  // Close reaction picker on outside click
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (
        reactionPicker.visible &&
        !event.target.closest('.reaction-picker') &&
        !event.target.closest('.sent-message p, .received-message p')
      ) {
        setReactionPicker({ messageId: null, visible: false });
      }
    };
    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  }, [reactionPicker]);

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
    setContactedUsernames([]);
    setReactions({});
    setShowReactions(true);
    setSearchTerm('');
    socket.disconnect();
  };

  // Scroll to bottom
  useEffect(() => {
    if (messageBoxRef.current) {
      messageBoxRef.current.scrollTop = messageBoxRef.current.scrollHeight;
    }
  }, [messages]);

  // Modal handlers
  const showProfilePicModal = () => setIsProfilePicModalOpen(true);
  const closeProfilePicModal = () => setIsProfilePicModalOpen(false);
  const showContactPicModal = (contactUsername, contactProfilePic) => {
    setContactModal({ isOpen: true, username: contactUsername, profilePic: contactProfilePic });
  };
  const closeContactModal = () => {
    setContactModal({ isOpen: false, username: '', profilePic: null });
  };

  const showProfile = () => setView('profile');
  const showInfo = () => setView('info');

  return (
    <ErrorBoundary>
      {isAuthenticated ? (
        <div className="chat-container">
          {view === 'profile' && <UserProfile username={username} profilePic={profilePic} setView={setView} />}
          {view === 'info' && <InfoPage setView={setView} />}
          {isProfilePicModalOpen && (
            <ProfilePicModal profilePic={profilePic} username={username} onClose={closeProfilePicModal} />
          )}
          {contactModal.isOpen && (
            <ProfilePicModal
              profilePic={contactModal.profilePic}
              username={contactModal.username}
              onClose={closeContactModal}
            />
          )}
          <div className="sidebar-icons">
            <div className="icon" onClick={() => { setView('chat'); setRecipient(''); setMessages([]); }}>
              <BsChatLeft size={24} />
            </div>
            <div className="icon" onClick={showProfile}>
              <FiUser size={24} />
            </div>
            <div className="icon" onClick={showInfo}>
              <BsInfoCircle size={24} />
            </div>
            <img
              src={profilePic ? `${backendUrl}/Uploads/${profilePic}` : `https://placehold.co/40?text=${username.charAt(0)}`}
              alt={username}
              className="avatar"
            />
          </div>
          <Sidebar
            username={username}
            users={filteredUsers}
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
            showContactPicModal={showContactPicModal}
            isSearching={isSearching}
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
                  <p className="empty-convo">
                    Convo
                    <br />
                    where connection comes to life
                  </p>
                ) : messages.length === 0 ? (
                  <p className="empty-convo">No messages yet. Start the conversation!</p>
                ) : (
                  messages.map((msg, index) => (
                    <Message
                      key={msg.messageId || `message-${index}`}
                      msg={msg}
                      username={username}
                      toggleReactionPicker={toggleReactionPicker}
                      reactionPicker={reactionPicker}
                      handleReaction={handleReaction}
                      showReactions={showReactions}
                      reactions={reactions}
                    />
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
                  isUploading={isUploading}
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
            showProfilePicModal={showProfilePicModal}
            theme={theme}
            toggleTheme={toggleTheme}
            showReactions={showReactions}
            setShowReactions={setShowReactions}
          />
        </div>
      ) : (
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
                  autoComplete="current-password"
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
                  autoComplete="new-password"
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
          <div className="branding">
            <div className="chat-icon"></div>
            <h1>CONVO</h1>
            <p>where connection comes to life</p>
          </div>
        </div>
      )}
    </ErrorBoundary>
  );
}

export default App;