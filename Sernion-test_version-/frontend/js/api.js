/**
 * Sernion Mark API Client
 * Handles communication with the Django backend
 */

class SernionMarkAPI {
    constructor(baseURL = 'http://localhost:8000/api/v1') {
        this.baseURL = baseURL;
        this.token = localStorage.getItem('access_token');
    }

    // Set authentication tokens
    setTokens(accessToken, refreshToken) {
        // Backward-compatible: store only access token for DRF TokenAuthentication
        this.token = accessToken;
        localStorage.setItem('access_token', accessToken);
    }

    // Clear authentication tokens
    clearTokens() {
        this.token = null;
        localStorage.removeItem('access_token');
        localStorage.removeItem('user_data');
    }

    // Get request headers
    getHeaders() {
        const headers = {
            'Content-Type': 'application/json',
        };
        
        if (this.token) {
            // DRF TokenAuthentication expects: Authorization: Token <key>
            headers['Authorization'] = `Token ${this.token}`;
        }
        
        return headers;
    }

    // Make API request
    async makeRequest(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            headers: this.getHeaders(),
            ...options
        };

        try {
            const response = await fetch(url, config);
            if (response.status === 401) {
                // Invalid/expired token; clear and redirect if applicable
                this.clearTokens();
            }
            return await this.handleResponse(response);
        } catch (error) {
            console.error('API request failed:', error);
            throw new Error('Network error occurred');
        }
    }

    // Make multipart/form-data request
    async makeFormRequest(endpoint, formData, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const headers = {};
        if (this.token) headers['Authorization'] = `Token ${this.token}`;
        const config = {
            method: options.method || 'POST',
            headers,
            body: formData,
        };
        try {
            const response = await fetch(url, config);
            if (response.status === 401) {
                this.clearTokens();
            }
            return await this.handleResponse(response);
        } catch (error) {
            console.error('API multipart request failed:', error);
            throw new Error('Network error occurred');
        }
    }

    // Handle API response
    async handleResponse(response) {
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || `HTTP ${response.status}`);
        }
        
        return data;
    }

    // No refresh token flow for DRF TokenAuthentication

    // Authentication Methods

    async register(userData) {
        const response = await this.makeRequest('/auth/register/', {
            method: 'POST',
            body: JSON.stringify(userData)
        });

        if (response.success && response.token) {
            this.setTokens(response.token, null);
            localStorage.setItem('user_data', JSON.stringify(response.user));
        }

        return response;
    }

    async login(credentials) {
        const response = await this.makeRequest('/auth/login/', {
            method: 'POST',
            body: JSON.stringify(credentials)
        });

        if (response.success && response.token) {
            this.setTokens(response.token, null);
            localStorage.setItem('user_data', JSON.stringify(response.user));
        }

        return response;
    }

    async logout() {
        try {
            await this.makeRequest('/auth/logout/', {
                method: 'POST'
            });
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            this.clearTokens();
        }
    }

    async verifyToken() {
        try {
            const response = await this.makeRequest('/auth/verify/');
            return response.success;
        } catch (error) {
            return false;
        }
    }

    // User Profile Methods

    async getProfile() {
        return await this.makeRequest('/user/profile/');
    }

    async updateProfile(profileData) {
        return await this.makeRequest('/user/profile/', {
            method: 'PUT',
            body: JSON.stringify(profileData)
        });
    }

    async changePassword(passwordData) {
        return await this.makeRequest('/user/change-password/', {
            method: 'POST',
            body: JSON.stringify(passwordData)
        });
    }

    // Password Reset Methods

    async requestPasswordReset(email) {
        return await this.makeRequest('/auth/password-reset/', {
            method: 'POST',
            body: JSON.stringify({ email })
        });
    }

    async confirmPasswordReset(token, newPassword) {
        return await this.makeRequest('/auth/password-reset/confirm/', {
            method: 'POST',
            body: JSON.stringify({
                token,
                new_password: newPassword,
                new_password_confirm: newPassword
            })
        });
    }

    // Health Check
    async healthCheck() {
        return await this.makeRequest('/health/');
    }

    // Admin summary
    async adminSummary() {
        return await this.makeRequest('/health/admin-summary/');
    }

    // Projects
    async getProjects() {
        return await this.makeRequest('/projects/');
    }

    async createProject(projectData) {
        return await this.makeRequest('/projects/', {
            method: 'POST',
            body: JSON.stringify(projectData)
        });
    }

    async getProject(projectId) {
        return await this.makeRequest(`/projects/${projectId}/`);
    }

    async updateProject(projectId, data) {
        return await this.makeRequest(`/projects/${projectId}/`, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }

    async deleteProject(projectId) {
        return await this.makeRequest(`/projects/${projectId}/`, {
            method: 'DELETE'
        });
    }

    async getProjectCounts(projectId) {
        return await this.makeRequest(`/projects/${projectId}/counts/`);
    }

    async getAllCounts() {
        return await this.makeRequest('/projects/counts/');
    }

    async bumpProjectCounts(projectId, counts) {
        return await this.makeRequest(`/projects/${projectId}/bump/`, {
            method: 'POST',
            body: JSON.stringify(counts)
        });
    }

    // Datasets
    async listDatasets(projectId) {
        return await this.makeRequest(`/${projectId}/datasets/`);
    }

    async createDataset(projectId, data) {
        return await this.makeRequest(`/${projectId}/datasets/`, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    async deleteDataset(projectId, datasetId) {
        return await this.makeRequest(`/${projectId}/datasets/${datasetId}/`, {
            method: 'DELETE'
        });
    }

    async listItems(projectId, datasetId) {
        return await this.makeRequest(`/${projectId}/datasets/${datasetId}/items/`);
    }

    async uploadItem(projectId, datasetId, file, type = 'image', meta = {}) {
        const form = new FormData();
        form.append('file', file);
        form.append('type', type);
        if (meta && Object.keys(meta).length) {
            form.append('meta', JSON.stringify(meta));
        }
        return await this.makeFormRequest(`/${projectId}/datasets/${datasetId}/upload/`, form);
    }

    // Annotation Tasks
    async listTasks(projectId) {
        return await this.makeRequest(`/projects/${projectId}/tasks/`);
    }

    async createTask(projectId, task) {
        return await this.makeRequest(`/projects/${projectId}/tasks/`, {
            method: 'POST',
            body: JSON.stringify(task)
        });
    }

    async getTask(projectId, taskId) {
        return await this.makeRequest(`/projects/${projectId}/tasks/${taskId}/`);
    }

    async updateTask(projectId, taskId, data) {
        return await this.makeRequest(`/projects/${projectId}/tasks/${taskId}/`, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }

    async deleteTask(projectId, taskId) {
        return await this.makeRequest(`/projects/${projectId}/tasks/${taskId}/`, {
            method: 'DELETE'
        });
    }

    async markTaskDone(projectId, taskId) {
        return await this.makeRequest(`/projects/${projectId}/tasks/${taskId}/done/`, {
            method: 'POST'
        });
    }

    // Teams
    async listTeams() {
        return await this.makeRequest('/teams/');
    }

    async createTeam(data) {
        return await this.makeRequest('/teams/', {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    async addTeamMember(teamId, userId, role = 'member') {
        return await this.makeRequest(`/teams/${teamId}/add-member/`, {
            method: 'POST',
            body: JSON.stringify({ user_id: userId, role })
        });
    }

    async removeTeamMember(teamId, userId) {
        return await this.makeRequest(`/teams/${teamId}/remove-member/`, {
            method: 'POST',
            body: JSON.stringify({ user_id: userId })
        });
    }

    async shareProjectWithTeam(projectId, teamId) {
        return await this.makeRequest(`/teams/share/${projectId}/${teamId}/`, {
            method: 'POST'
        });
    }

    // Get current user data
    getCurrentUser() {
        const userData = localStorage.getItem('user_data');
        return userData ? JSON.parse(userData) : null;
    }

    // Check if user is authenticated
    isAuthenticated() {
        return !!this.token;
    }

    // WebSocket helper for live project counts
    connectCountsWebSocket(projectId, onMessage) {
        const wsUrl = this.baseURL.replace('http', 'ws').replace('/api/v1', '') + `/ws/projects/${projectId}/counts/`;
        const ws = new WebSocket(wsUrl);
        ws.onmessage = (evt) => {
            try {
                const parsed = JSON.parse(evt.data);
                if (parsed.type === 'counts' && onMessage) {
                    onMessage(parsed.data);
                }
            } catch (e) {
                console.error('WS parse error', e);
            }
        };
        ws.onerror = (e) => console.error('WS error', e);
        return ws;
    }
}

// Global API instance
const api = new SernionMarkAPI();

// Frontend Integration Functions

// Update login form to use API
function setupLoginForm() {
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(loginForm);
            const usernameOrEmail = formData.get('username') || formData.get('email');
            const credentials = {
                username: usernameOrEmail,
                password: formData.get('password')
            };

            try {
                showLoading('Logging in...');
                const response = await api.login(credentials);
                
                if (response.success) {
                    showSuccess('Login successful!');
                    // Redirect to dashboard
                    setTimeout(() => {
                        window.location.href = 'dashboard.html';
                    }, 1000);
                } else {
                    showError(response.errors || 'Login failed');
                }
            } catch (error) {
                showError(error.message);
            } finally {
                hideLoading();
            }
        });
    }
}

// Update signup form to use API
function setupSignupForm() {
    const signupForm = document.getElementById('signupForm');
    if (signupForm) {
        signupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(signupForm);
            const userData = {
                username: formData.get('username'),
                email: formData.get('email'),
                password: formData.get('password'),
                password_confirm: formData.get('password_confirm'),
                full_name: formData.get('full_name')
            };

            try {
                showLoading('Creating account...');
                const response = await api.register(userData);
                
                if (response.success) {
                    showSuccess('Account created successfully!');
                    // Redirect to dashboard
                    setTimeout(() => {
                        window.location.href = 'dashboard.html';
                    }, 1000);
                } else {
                    showError(response.errors || 'Registration failed');
                }
            } catch (error) {
                showError(error.message);
            } finally {
                hideLoading();
            }
        });
    }
}

// Setup logout functionality
function setupLogout() {
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            try {
                await api.logout();
                window.location.href = 'login.html';
            } catch (error) {
                console.error('Logout error:', error);
                window.location.href = 'login.html';
            }
        });
    }
}

// Check authentication on page load
async function checkAuth() {
    if (api.isAuthenticated()) {
        const isValid = await api.verifyToken();
        if (!isValid) {
            api.clearTokens();
            if (window.location.pathname !== '/login.html') {
                window.location.href = 'login.html';
            }
        }
    } else {
        // Redirect to login if not authenticated and not on login/signup pages
        const currentPage = window.location.pathname;
        if (!currentPage.includes('login.html') && !currentPage.includes('signup.html')) {
            window.location.href = 'login.html';
        }
    }
}

// UI Helper Functions

function showLoading(message = 'Loading...') {
    // Create or update loading indicator
    let loadingDiv = document.getElementById('loading');
    if (!loadingDiv) {
        loadingDiv = document.createElement('div');
        loadingDiv.id = 'loading';
        loadingDiv.className = 'loading-overlay';
        loadingDiv.innerHTML = `
            <div class="loading-spinner">
                <div class="spinner"></div>
                <p>${message}</p>
            </div>
        `;
        document.body.appendChild(loadingDiv);
    }
    loadingDiv.style.display = 'flex';
}

function hideLoading() {
    const loadingDiv = document.getElementById('loading');
    if (loadingDiv) {
        loadingDiv.style.display = 'none';
    }
}

function showSuccess(message) {
    showNotification(message, 'success');
}

function showError(message) {
    showNotification(message, 'error');
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    setupLoginForm();
    setupSignupForm();
    setupLogout();
    checkAuth();
});

// Export for use in other scripts
window.SernionMarkAPI = SernionMarkAPI;
window.api = api;
