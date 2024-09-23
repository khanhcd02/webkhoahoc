// tokenHandler.js

// Lấy thông tin từ accessToken
function parseJwt(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));

        return JSON.parse(jsonPayload);
    } catch (e) {
        console.error('Invalid Token');
        return null;
    }
}

// Kiểm tra và làm mới accessToken
function checkAndRefreshToken() {
    const accessToken = getCookie('accessToken'); // Lấy accessToken từ cookie

    if (accessToken) {
        const tokenData = parseJwt(accessToken);
        if (tokenData) {
            const currentTime = Math.floor(Date.now() / 1000); // Lấy thời gian hiện tại tính bằng giây

            // Nếu token sắp hết hạn trong vòng 2 phút (120 giây)
            if (tokenData.exp - currentTime < 120) {
                refreshAccessToken(); // Gọi hàm làm mới token
            }
        }
    }
}

// Hàm gọi API làm mới token
function refreshAccessToken() {
    fetch('/auth/token', {
        method: 'POST',
        credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
        if (data.accessToken) {
            console.log('Token đã được làm mới');
            // Cập nhật lại cookie accessToken nếu cần
            document.cookie = `accessToken=${data.accessToken}; path=/;`;
        } else {
            console.error('Không thể làm mới token');
        }
    })
    .catch(error => {
        console.error('Error refreshing token:', error);
    });
}

// Lấy cookie từ tên
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

// Kiểm tra và làm mới token mỗi 1 phút
setInterval(checkAndRefreshToken, 60000);
