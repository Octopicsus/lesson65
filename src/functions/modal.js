let currentEditingUser = null;

export function editUser(userId, currentName) {
    currentEditingUser = { id: userId, name: currentName };
    const modal = document.getElementById('editModal');
    const input = document.getElementById('editNameInput');
    
    input.value = currentName;
    modal.style.display = 'block';
}

export function closeModal() {
    const modal = document.getElementById('editModal');
    modal.style.display = 'none';
    currentEditingUser = null;
}

export async function saveEdit() {
    if (!currentEditingUser) return;
    
    const newName = document.getElementById('editNameInput').value.trim();
    
    if (!newName) {
        alert('Please enter a name');
        return;
    }
    
    if (newName === currentEditingUser.name) {
        closeModal();
        return;
    }
    
    try {
        const response = await fetch('/newlist', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                id: currentEditingUser.id, 
                newName: newName 
            })
        });

        const result = await response.json();
        
        if (response.ok) {
            alert('User updated successfully');
            closeModal();
            location.reload();
        } else {
            alert('Error: ' + result.message);
        }
    } catch (error) {
        alert('Error updating user: ' + error.message);
    }
}
