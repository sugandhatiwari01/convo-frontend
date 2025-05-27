import React, { useState, useEffect, useRef, useCallback } from 'react';
import io from 'socket.io-client';
import axios from 'axios';
import './App.css';
import { IoSearchOutline, IoSettingsOutline, IoSendSharp, IoAttachOutline, IoChevronBack } from 'react-icons/io5';
import { BsChatLeft, BsInfoCircle } from 'react-icons/bs';
import { FiUser } from 'react-icons/fi';

// API and backend URLs
const apiBase = process.env.REACT_APP_API_BASE || 'https://convodb1.onrender.com/api';
const backendUrl = process.env.REACT_APP_BACKEND_URL || 'https://convodb1.onrender.com';

// Axios instance with default configuration
const api = axios.create({
  baseURL: apiBase,
  withCredentials: true,
});

// Socket.IO connection
const socket = io(backendUrl, {
  withCredentials: true,
  transports: ['websocket', 'polling'],
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
const Sidebar = ({ username, users, searchTerm, setSearchTerm, recipient, setRecipient, loadChatHistory, unreadMessages, userDPs, profilePic, showProfile, showInfo, setView, isSidebarOpen, toggleSidebar, onlineUsers, showContactPicModal }) => {
  return (
    <div className={`sidebar ${isSidebarOpen ? 'open' : ''}`}>
      <div className="sidebar-header">
        <h1>Convo</h1>
        <div className="search-input-container">
          <input
            type="text"
            placeholder="Search..."
            className="search-input"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          <IoSearchOutline className="search-icon" />
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
                setView('chat');
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
              <span className="user-name">{user}</span>
              {unreadMessages[user] > 0 && (
                <span className="message-count">{unreadMessages[user]}</span>
              )}
              <small>{onlineUsers.includes(user) ? 'Online' : 'Offline'}</small>
            </div>
          ))
        ) : (
          <p>No recent contacts</p>
        )}
      </div>
    </div>
  );
};

// ChatHeader Component
const ChatHeader = ({ recipient, username, profilePic, userDPs, setIsSettingsOpen, toggleSidebar, onlineUsers }) => {
  return (
    <div className="chat-header">
      <div className="user-info">
        <IoChevronBack className="back-button" onClick={() => toggleSidebar(true)} />
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
        <IoSettingsOutline />
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
          src={profilePic ? `${backendUrl}/Uploads/${profilePic}` : `https://via.placeholder.com/120?text=${username.charAt(0)}`}
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
    <div className="modal-overlay">
      <div className="modal-content">
        <button className="modal-close" onClick={onClose}>×</button>
        <img
          src={profilePic || `https://via.placeholder.com/300?text=${username.charAt(0)}`}
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
      <div className="profile-section">
        <img
          src={profilePic ? `${backendUrl}/Uploads/${profilePic}` : `https://via.placeholder.com/120?text=${username.charAt(0)}`}
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
          <div className="option" onClick={showProfilePicModal}>View Profile Picture</div>
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
              <div className={`theme-toggle ${theme === 'dark' ? 'checked' : ''}`}>
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
        placeholder="Enter Text..."
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
        <IoAttachOutline size={20} />
      </label>
      <button onClick={sendMessage} className="send-button">
        <IoSendSharp size={18} />
      </button>
    </div>
  );
};

// Main App Component
function App() {
  const [isSignupActive, setIsSignupActive] = useState(false);
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
  const [isProfilePicModalOpen, setIsProfilePicModalOpen] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'light');
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [contactedUsernames, setContactedUsernames] = useState(JSON.parse(localStorage.getItem('contactedUsernames')) || []);
  const [contactModal, setContactModal] = useState({ isOpen: false, username: '', profilePic: null });
  const [reactions, setReactions] = useState(JSON.parse(localStorage.getItem('reactions')) || {});
  const [showReactions, setShowReactions] = useState(JSON.parse(localStorage.getItem('showReactions')) || true);
  const [reactionPicker, setReactionPicker] = useState({ messageId: null, visible: false });
  const messageBoxRef = useRef(null);
  const fileInputRef = useRef(null);
  const profilePicInputRef = useRef(null);

  // Persist contactedUsernames and reactions in localStorage
  useEffect(() => {
    localStorage.setItem('contactedUsernames', JSON.stringify(contactedUsernames));
  }, [contactedUsernames]);

  useEffect(() => {
    localStorage.setItem('reactions', JSON.stringify(reactions));
  }, [reactions]);

  useEffect(() => {
    localStorage.setItem('showReactions', JSON.stringify(showReactions));
  }, [showReactions]);

  // Apply theme to body and update SVG
  useEffect(() => {
    document.body.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);

    const chatIcon = document.querySelector('.branding .chat-icon');
    if (chatIcon) {
      const strokeColor = theme === 'light' ? '#945D5D' : '#D4A373';
      const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="${strokeColor}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"></path></svg>`;
      chatIcon.style.background = `url('data:image/svg+xml;utf8,${encodeURIComponent(svg)}') no-repeat center`;
      chatIcon.style.backgroundSize = 'contain';
    }
  }, [theme]);

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
    if (username) {
      try {
        const response = await retry(() =>
          api.get(`/messages/unread/${username.toLowerCase()}`)
        );
        setUnreadMessages(response.data);
      } catch (error) {
        console.error('Unread messages error:', {
          message: error.message,
          response: error.response?.data,
          status: error.response?.status,
        });
      }
    }
  }, [username]);

  // Fetch users
  const fetchUsers = useCallback(
    async (query = '') => {
      if (!username) {
        setError('Username not set');
        return;
      }
      try {
        const response = await retry(() =>
          api.get('/users/search', {
            params: { query, currentUser: username.toLowerCase() },
          })
        );
        let uniqueUsers = [];
        if (response.data && Array.isArray(response.data)) {
          uniqueUsers = [...new Set([...response.data])].filter(
            (u) => u.toLowerCase() !== username.toLowerCase()
          );
          if (query) {
            uniqueUsers = [...new Set([...uniqueUsers, ...contactedUsernames])].filter(
              (u) => u.toLowerCase() !== username.toLowerCase()
            );
          } else {
            uniqueUsers = [...contactedUsernames].filter(
              (u) => u.toLowerCase() !== username.toLowerCase()
            );
          }
          setUsers(uniqueUsers);
          const dpPromises = uniqueUsers.map((user) =>
            api
              .get(`/user/profile-pic/${user}`)
              .then((res) => ({ user, profilePic: res.data.profilePic }))
              .catch((err) => {
                console.error(`Profile pic error for ${user}:`, err.message);
                return { user, profilePic: null };
              })
          );
          const dps = await Promise.all(dpPromises);
          setUserDPs(Object.fromEntries(dps.map(({ user, profilePic }) => [user, profilePic])));
          if (uniqueUsers.length > 0) fetchUnreadMessages();
        }
      } catch (error) {
        console.error('Fetch users error:', {
          message: error.message,
          response: error.response?.data,
          status: error.response?.status,
        });
        setError('Failed to load contacts. Please try again.');
        if (query) {
          setUsers([...contactedUsernames].filter((u) => u.toLowerCase() !== username.toLowerCase()));
        } else {
          setUsers([]);
        }
      }
    },
    [username, fetchUnreadMessages, contactedUsernames]
  );

  // Socket and authentication logic
  useEffect(() => {
    const token = localStorage.getItem('token');
    const storedUsername = localStorage.getItem('username');
    if (token && storedUsername) {
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      setIsAuthenticated(true);
      setUsername(storedUsername);
      socket.emit('registerUser', storedUsername);
      fetchUsers();
      fetchUnreadMessages();
      api
        .get(`/user/profile-pic/${storedUsername}`)
        .then((response) => setProfilePic(response.data.profilePic))
        .catch((err) => console.error('Failed to fetch profile pic:', err));
      setView('chat');
    }

    const urlParams = new URLSearchParams(window.location.search);
    const tokenParam = urlParams.get('token');
    const usernameParam = urlParams.get('username');
    if (tokenParam && usernameParam) {
      localStorage.setItem('token', tokenParam);
      localStorage.setItem('username', decodeURIComponent(usernameParam));
      api.defaults.headers.common['Authorization'] = `Bearer ${tokenParam}`;
      setIsAuthenticated(true);
      setUsername(decodeURIComponent(usernameParam));
      socket.emit('registerUser', decodeURIComponent(usernameParam));
      fetchUsers();
      fetchUnreadMessages();
      api
        .get(`/user/profile-pic/${decodeURIComponent(usernameParam)}`)
        .then((response) => setProfilePic(response.data.profilePic))
        .catch((err) => console.error('Failed to fetch profile pic:', err));
      setView('chat');
      window.history.replaceState({}, document.title, '/');
    }

    if (isAuthenticated) {
      const handleReceiveMessage = (msg) => {
        if (msg.username !== username && !messages.some((m) => m.messageId === msg.messageId)) {
          setContactedUsernames((prev) => (prev.includes(msg.username) ? prev : [...prev, msg.username]));
          if (msg.username === recipient) {
            setMessages((prev) => [...prev, msg]);
            setUnreadMessages((prev) => ({
              ...prev,
              [msg.username]: 0,
            }));
            api.post(`/messages/mark-read/${username}/${msg.username}`);
          } else {
            setUnreadMessages((prev) => ({
              ...prev,
              [msg.username]: (prev[msg.username] || 0) + 1,
            }));
          }
        }
      };

      const handleUserStatus = ({ user, status }) => {
        setOnlineUsers((prev) => {
          if (status === 'online' && !prev.includes(user)) {
            return [...prev, user];
          } else if (status === 'offline' && prev.includes(user)) {
            return prev.filter((u) => u !== user);
          }
          return prev;
        });
      };

      socket.on('connect', () => console.log('Connected to server'));
      socket.on('receiveMessage', handleReceiveMessage);
      socket.on('userTyping', (data) => {
        if (data.username === recipient) {
          setTyping(data.username);
          setTimeout(() => setTyping(''), 2000);
        }
      });
      socket.on('userListUpdate', (updatedUsers) => {
        if (!searchTerm) {
          const uniqueUsers = [...new Set([...updatedUsers, ...contactedUsernames])].filter((u) => u !== username);
          setUsers(uniqueUsers);
        }
      });
      socket.on('userStatus', handleUserStatus);

      return () => {
        socket.off('receiveMessage', handleReceiveMessage);
        socket.off('userTyping');
        socket.off('userListUpdate');
        socket.off('userStatus');
      };
    }
  }, [isAuthenticated, username, fetchUsers, fetchUnreadMessages, recipient, contactedUsernames, searchTerm]);

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
        setUnreadMessages((prev) => ({
          ...prev,
          [selectedRecipient]: 0,
        }));
        setContactedUsernames((prev) => (prev.includes(selectedRecipient) ? prev : [...prev, selectedRecipient]));
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
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      setError('Username must be 3-20 characters (letters, numbers, underscores)');
      return;
    }
    if (!/^[\w-.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
      setError('Invalid email format');
      return;
    }
    if (password.length < 6) {
      setError('Password must be at least 6 characters');
      return;
    }
    try {
      await api.post('/auth/register', { email, username, password });
      setView('login');
      setError('');
    } catch (error) {
      setError(error.response?.data?.message || 'Registration failed');
      console.error('Registration error:', error);
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
      fetchUnreadMessages();
      setError('');
    } catch (error) {
      setError(error.response?.data?.message || 'Login failed');
      console.error('Login error:', error);
    }
  };

  // Send text message
  const sendMessage = async () => {
    if (message.trim() && isAuthenticated && recipient) {
      const msg = {
        messageId: Date.now().toString(),
        username,
        text: message,
        timestamp: new Date(),
        type: 'text',
      };
      socket.emit('sendMessage', { recipient, message: msg.text, type: 'text' });
      setMessages((prev) => [...prev, msg]);
      setContactedUsernames((prev) => (prev.includes(recipient) ? prev : [...prev, recipient]));
      setMessage('');
      socket.emit('stopTyping', { recipient });
      await fetchUnreadMessages();
    }
  };

  // Send file
  const sendFile = async (event) => {
    const file = event.target.files[0];
    if (file && isAuthenticated && recipient && !fileInputRef.current?.disabled) {
      fileInputRef.current.disabled = true;
      const formData = new FormData();
      formData.append('file', file);
      formData.append('recipient', recipient);
      formData.append('username', username);
      formData.append('timestamp', new Date().toISOString());

      try {
        const response = await api.post('/messages/sendFile', formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
        });
        const msg = response.data;
        setMessages((prev) => [...prev, msg]);
        socket.emit('sendMessage', {
          recipient,
          message: msg,
          type: msg.type,
          file: msg.file,
        });
        setContactedUsernames((prev) => (prev.includes(recipient) ? prev : [...prev, recipient]));
        await fetchUnreadMessages();
      } catch (error) {
        console.error('Failed to send file:', error.response?.data?.message || error.message);
      } finally {
        fileInputRef.current.disabled = false;
        fileInputRef.current.value = '';
      }
    }
  };

  // Update profile picture
  const updateProfilePic = async (event) => {
    const file = event.target.files[0];
    if (file && isAuthenticated) {
      profilePicInputRef.current.disabled = true;
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
      } finally {
        profilePicInputRef.current.disabled = false;
        profilePicInputRef.current.value = '';
      }
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

  // Handle reactions
  const handleReaction = (messageId, emoji) => {
    setReactions((prev) => {
      const messageReactions = prev[messageId] || {};
      const userReactions = messageReactions[username] || [];
      let updatedUserReactions;
      if (userReactions.includes(emoji)) {
        updatedUserReactions = userReactions.filter((e) => e !== emoji);
      } else {
        updatedUserReactions = [...userReactions, emoji];
      }
      const updatedMessageReactions = {
        ...messageReactions,
        [username]: updatedUserReactions,
      };
      return {
        ...prev,
        [messageId]: updatedMessageReactions,
      };
    });
    setReactionPicker({ messageId: null, visible: false });
  };

  const toggleReactionPicker = (messageId) => {
    setReactionPicker((prev) => ({
      messageId,
      visible: prev.messageId === messageId ? !prev.visible : true,
    }));
  };

  // Logout
  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    localStorage.removeItem('contactedUsernames');
    localStorage.removeItem('reactions');
    localStorage.removeItem('showReactions');
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
    socket.disconnect();
  };

  // Debounced fetch users
  const debouncedFetchUsers = useCallback(
    debounce((query) => {
      fetchUsers(query);
    }, 300),
    [fetchUsers]
  );

  // Compute contacted users
  const contactedUsers = users.filter((user) =>
    unreadMessages[user] || contactedUsernames.includes(user)
  );

  // Scroll to bottom of message box
  useEffect(() => {
    if (messageBoxRef.current) {
      messageBoxRef.current.scrollTop = messageBoxRef.current.scrollHeight;
    }
  }, [messages]);

  // Fetch users on search
  useEffect(() => {
    if (searchTerm) {
      debouncedFetchUsers(searchTerm);
    } else {
      fetchUsers();
    }
  }, [searchTerm, debouncedFetchUsers, fetchUsers]);

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
  const toggleSidebar = (value) => setIsSidebarOpen(value);

  if (!isAuthenticated) {
    return (
     <div className="signup-container">
        <div className={`signup-box ${isSignupActive ? 'signup-mode' : ''}`}>
          <h2>{view === 'login' ? 'Sign In' : 'Sign Up'}</h2>
          <div className="signup-nav">
            <div className="signup">
              <button
                className={`nav ${view === 'register' ? 'active-tab' : ''}`}
                onClick={() => {
                  setView('register');
                  setIsSignupActive(true);
                }}
              >
                Sign Up
              </button>
            </div>
            <div className="signin">
              <button
                className={`nav ${view === 'login' ? 'active-tab' : ''}`}
                onClick={() => {
                  setView('login');
                  setIsSignupActive(false);
                }}
              >
                Sign In
              </button>
            </div>
          </div>
          <div className="signup-form">
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
        <div className="branding">
          <div className="chat-icon"></div>
          <h1>CONVO</h1>
          <p>where connection comes to life</p>
        </div>
      </div>
  
    );
  }

  return (
    <div className="chat-container">
      {view === 'profile' && <UserProfile username={username} profilePic={profilePic} setView={setView} />}
      {view === 'info' && <InfoPage setView={setView} />}
      {isProfilePicModalOpen && (
        <ProfilePicModal
          profilePic={profilePic}
          username={username}
          onClose={closeProfilePicModal}
        />
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
    <BsChatLeft />
  </div>
  <div className="icon" onClick={showProfile}>
    <FiUser />
  </div>
  <div className="icon" onClick={showInfo}>
    <BsInfoCircle />
  </div>
  <img
    src={profilePic ? `${backendUrl}/Uploads/${profilePic}` : `https://via.placeholder.com/40?text=${username.charAt(0)}`}
    alt={username}
    className="icon"
  />
</div>
      <Sidebar
        username={username}
        users={searchTerm ? users : contactedUsers}
        searchTerm={searchTerm}
        setSearchTerm={setSearchTerm}
        recipient={recipient}
        setRecipient={setRecipient}
        loadChatHistory={loadChatHistory}
        unreadMessages={unreadMessages}
        userDPs={userDPs}
        profilePic={profilePic}
        showProfile={showProfile}
        showInfo={showInfo}
        setView={setView}
        isSidebarOpen={isSidebarOpen}
        toggleSidebar={toggleSidebar}
        onlineUsers={onlineUsers}
        showContactPicModal={showContactPicModal}
      />
      {view === 'chat' && (
        <div className="main-chat">
          <ChatHeader
            recipient={recipient}
            username={username}
            profilePic={profilePic}
            userDPs={userDPs}
            setIsSettingsOpen={setIsSettingsOpen}
            toggleSidebar={toggleSidebar}
            onlineUsers={onlineUsers}
          />
          <div className="message-box" ref={messageBoxRef}>
            {!recipient ? (
              <p className="empty-convo">Convo<br />where connection comes to life</p>
            ) : messages.length === 0 ? (
              <p className="empty-convo">No messages yet. Start the conversation!</p>
            ) : (
              messages.reduce((acc, msg, index) => {
                const currentDate = new Date(msg.timestamp).toLocaleDateString('en-US', {
                  year: 'numeric',
                  month: 'long',
                  day: 'numeric',
                });
                const prevMsg = messages[index - 1];
                const prevDate = prevMsg
                  ? new Date(prevMsg.timestamp).toLocaleDateString('en-US', {
                      year: 'numeric',
                      month: 'long',
                      day: 'numeric',
                    })
                  : null;

                if (index === 0 || currentDate !== prevDate) {
                  acc.push(
                    <div key={`date-${currentDate}-${index}`} className="date-separator">
                      <span>{currentDate}</span>
                    </div>
                  );
                }

                acc.push(
                  <div
                    key={msg.messageId || index}
                    className={msg.username === username ? 'sent-message-container' : 'received-message-container'}
                  >
                    {msg.type === 'text' ? (
                      <div className={msg.username === username ? 'sent-message' : 'received-message'}>
                        <p onClick={() => toggleReactionPicker(msg.messageId)} style={{ cursor: 'pointer' }}>
                          {msg.text}
                          <small>{new Date(msg.timestamp).toLocaleTimeString()}</small>
                        </p>
                        {reactionPicker.visible && reactionPicker.messageId === msg.messageId && (
                          <div className="reaction-picker">
                            {['👍', '❤️', '😂', '😮', '😢'].map((emoji) => (
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
                            {msg.type === 'image' ? 'View Image' : 'View Document'}
                          </a>
                        )}
                        <small>{new Date(msg.timestamp).toLocaleTimeString()}</small>
                      </div>
                    )}
                  </div>
                );
                return acc;
              }, [])
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
        showProfilePicModal={showProfilePicModal}
        theme={theme}
        toggleTheme={toggleTheme}
        showReactions={showReactions}
        setShowReactions={setShowReactions}
      />
    </div>
  );
}

export default App;