import React, { useState } from 'react';
import { Clock, Plus, MoreVertical, Archive, Trash2, EyeOff, Bell } from 'lucide-react';

export default function Sidebar({ 
  chats = [], 
  activeChatId, 
  onSelectChat, 
  onNewChat, 
  onArchive,
  onDelete,
  showArchived = false,
  onToggleArchived,
  onOpenNotifications,
}) {

  const [openMenuId, setOpenMenuId] = useState(null); // session id whose menu is open

  const activeChats = chats.filter((c) => !c.archived);
  const archivedChats = chats.filter((c) => c.archived);

  const handleArchive = (id, currentlyArchived) => {
    setOpenMenuId(null);
    onArchive(id, !currentlyArchived);
  };

  const handleDelete = (id) => {
    if (!window.confirm('Delete this chat? This cannot be undone.')) return;
    setOpenMenuId(null);
    onDelete(id);
  };

  const renderChatRow = (chat) => {
    const isActive = activeChatId === chat.id;
    const menuOpen = openMenuId === chat.id;
    return (
      <div key={chat.id} style={{ display: 'flex', flexDirection: 'column' }}>
        <div className="chat-row" style={{ display: 'flex', alignItems: 'center', gap: '4px', position: 'relative' }}>
          <button
            type="button"
            className="chat-row__main"
            onClick={() => onSelectChat(chat.id)}
            style={{
              width: '100%',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 10px',
              border: 'none',
              background: isActive ? 'rgba(56, 189, 248, 0.2)' : 'transparent',
              color: isActive ? '#38bdf8' : 'var(--text-muted)',
              borderLeft: isActive ? '3px solid #38bdf8' : 'transparent',
              borderRadius: '0 8px 8px 0',
              cursor: 'pointer',
              fontSize: '0.82rem',
              textAlign: 'left',
              transition: 'all 0.15s'
            }}
          >
            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
              {new Date(chat.updated_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </span>
            <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {chat.title || 'New Chat'}
            </span>
            {chat.archived && (
              <span style={{ fontSize: '0.65rem', color: '#94a3b8', marginLeft: '6px' }}>
                archived
              </span>
            )}
          </button>
          <button
            type="button"
            className="chat-options-trigger"
            aria-label={`Options for ${chat.title || 'New Chat'}`}
            aria-expanded={menuOpen}
            onClick={(e) => {
              e.stopPropagation();
              setOpenMenuId(menuOpen ? null : chat.id);
            }}
            style={{
              padding: '5px',
              border: 'none',
              background: 'transparent',
              color: 'var(--text-dim)',
              cursor: 'pointer',
              borderRadius: '6px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}
          >
            <MoreVertical size={16} />
          </button>
          {menuOpen && (
            <div style={{
              position: 'absolute',
              right: '0',
              top: '110%',
              background: '#090d16',
              border: '1px solid rgba(255,255,255,0.12)',
              borderRadius: '8px',
              boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
              zIndex: 50,
              minWidth: '150px'
            }}>
              <div style={{ padding: '6px 8px', fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                Options
              </div>
              <button
                type="button"
                onClick={() => handleArchive(chat.id, chat.archived)}
                style={{
                  width: '100%', display: 'flex', alignItems: 'center', gap: '10px',
                  padding: '8px 12px', border: 'none', background: 'transparent',
                  color: '#f8fafc', cursor: 'pointer', fontSize: '0.8rem',
                  textAlign: 'left'
                }}
              >
                {chat.archived ? <EyeOff size={14} /> : <Archive size={14} />}
                {chat.archived ? 'Unarchive' : 'Archive'}
              </button>
              <button
                type="button"
                onClick={() => handleDelete(chat.id)}
                style={{
                  width: '100%', display: 'flex', alignItems: 'center', gap: '10px',
                  padding: '8px 12px', border: 'none', background: 'transparent',
                  color: '#fb7185', cursor: 'pointer', fontSize: '0.8rem',
                  textAlign: 'left'
                }}
              >
                <Trash2 size={14} /> Delete
              </button>
            </div>
          )}
        </div>
      </div>
    );
  };

  return (
    <aside className="sidebar-panel" style={{
      width: '240px',
      background: 'rgba(10, 15, 26, 0.9)',
      borderRight: '1px solid rgba(255, 255, 255, 0.06)',
      display: 'flex',
      flexDirection: 'column',
      height: 'calc(100vh - 58px)',
      overflowY: 'auto'
    }}>
      <div style={{ padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            background: 'rgba(56, 189, 248, 0.15)',
            padding: '7px', borderRadius: '8px',
            border: '1px solid rgba(56, 189, 248, 0.3)'
          }}>
            <Clock size={16} color="#38bdf8" />
          </div>
          <div>
            <div style={{ fontSize: '0.85rem', fontWeight: 800, color: '#f8fafc' }}>
              Chats
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
              {activeChats.length} saved
            </div>
          </div>
        </div>
      </div>

      <div className="sidebar-chats" style={{ flex: 1, overflowY: 'auto', padding: '8px 4px' }}>
        {activeChats.length === 0 ? (
          <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.8rem' }}>
            No recent chats. Start a new conversation.
          </div>
        ) : (
          activeChats.map(renderChatRow)
        )}
      </div>

      {archivedChats.length > 0 && (
        <div style={{ padding: '8px 20px', borderTop: '1px solid rgba(255,255,255,0.06)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <button
            type="button"
            onClick={onToggleArchived}
            aria-expanded={showArchived}
            style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: '8px',
              padding: '6px 10px', border: 'none', background: 'transparent',
              color: '#38bdf8', cursor: 'pointer', fontSize: '0.75rem'
            }}
          >
            {showArchived ? <EyeOff size={14} /> : <Archive size={14} />}
            {showArchived ? 'Hide archived' : 'Show archived'}
          </button>
        </div>
      )}

      {showArchived && archivedChats.length > 0 && (
        <div style={{ padding: '4px 4px' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em', padding: '0 12px', marginBottom: '4px' }}>
            Archived
          </div>
          {archivedChats.map(renderChatRow)}
        </div>
      )}

      <div style={{ padding: '10px 14px', borderTop: '1px solid rgba(255,255,255,0.06)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
        <button
          type="button"
          onClick={onOpenNotifications}
          style={{
            width: '100%', display: 'flex', alignItems: 'center', gap: '8px',
            padding: '7px 12px', border: '1px solid rgba(255, 255, 255, 0.1)',
            borderRadius: '8px', background: 'rgba(255, 255, 255, 0.03)', color: 'var(--text-muted)',
            cursor: 'pointer', fontSize: '0.78rem', fontWeight: 600
          }}
        >
          <Bell size={14} color="#38bdf8" />
          <span>Notification Settings</span>
        </button>

        <button
          type="button"
          onClick={onNewChat}
          style={{
            width: '100%', display: 'flex', alignItems: 'center', gap: '10px',
            padding: '8px 12px', border: '1px solid rgba(56, 189, 248, 0.4)',
            borderRadius: '8px', background: 'transparent', color: '#38bdf8',
            cursor: 'pointer', fontSize: '0.82rem', fontWeight: 600
          }}
        >
          <Plus size={16} />
          <span className="sidebar-action-label">New Chat</span>
        </button>
      </div>

    </aside>
  );
}
