export async function deleteUser(userId) {
    if (confirm('Are you sure you want to delete this user?')) {
        try {
            const response = await fetch('/users', {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ id: userId })
            });

            const result = await response.json();
            
            if (response.ok) {
                alert('User deleted successfully');
                location.reload(); 
            } else {
                alert('Error: ' + result.message);
            }
        } catch (error) {
            alert('Error deleting user: ' + error.message);
        }
    }
}

export async function deleteNewListItem(itemId) {
    if (confirm('Are you sure you want to delete this item?')) {
        try {
            const response = await fetch('/newlist', {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ id: itemId })
            });

            const result = await response.json();
            
            if (response.ok) {
                alert('Item deleted successfully');
                location.reload(); 
            } else {
                alert('Error: ' + result.message);
            }
        } catch (error) {
            alert('Error deleting item: ' + error.message);
        }
    }
}

export async function copyAllUsers() {
    if (confirm('Are you sure you want to copy all users to Other List?')) {
        try {
            const response = await fetch('/copy-users', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            const result = await response.json();
            
            if (response.ok) {
                alert(`${result.copiedCount} users copied successfully`);
                location.reload(); 
            } else {
                alert('Error: ' + result.message);
            }
        } catch (error) {
            alert('Error copying users: ' + error.message);
        }
    }
}

export async function cleanAllUsers() {
    if (confirm('Are you sure you want to delete ALL items from Other List? This action cannot be undone!')) {
        try {
            const response = await fetch('/clean-newlist', {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            const result = await response.json();
            
            if (response.ok) {
                alert(`${result.deletedCount} items deleted successfully`);
                location.reload(); 
            } else {
                alert('Error: ' + result.message);
            }
        } catch (error) {
            alert('Error cleaning list: ' + error.message);
        }
    }
}
