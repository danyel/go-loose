package server

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danyel/go-loose/internal/avatar"
	"github.com/danyel/go-loose/internal/store"
)

// maxProfileBody bounds a profile update. It allows an avatar at its 2 MiB
// limit after base64 inflation plus the JSON envelope.
const maxProfileBody = 4 << 20

// maxDisplayName bounds a self-selected display name.
const maxDisplayName = 200

type profileResponse struct {
	ID                    string             `json:"id"`
	Email                 string             `json:"email"`
	DisplayName           string             `json:"display_name"`
	AvatarURL             string             `json:"avatar_url"`
	Memberships           []store.Membership `json:"memberships"`
	IsSystemAdministrator bool               `json:"is_system_administrator"`
	NameCustomized        bool               `json:"name_customized"`
	CreatedAt             time.Time          `json:"created_at"`
	LastLoginAt           time.Time          `json:"last_login_at"`
	ProfileUpdatedAt      *time.Time         `json:"profile_updated_at,omitempty"`
	AvatarUpdatedAt       *time.Time         `json:"avatar_updated_at,omitempty"`
}

func (s *Server) profilePage(w http.ResponseWriter, _ *http.Request) {
	s.serveEmbedded(w, "profile.html")
}

func (s *Server) profile(w http.ResponseWriter, r *http.Request) {
	profile, err := s.store.Profile(r.Context(), claimsFrom(r).UserID)
	if err != nil {
		s.handleStoreError(w, "load profile", err)
		return
	}
	writeJSON(w, http.StatusOK, s.profileResponse(profile))
}

func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request) {
	var request struct {
		DisplayName  *string `json:"display_name"`
		Avatar       string  `json:"avatar"`
		RemoveAvatar bool    `json:"remove_avatar"`
	}
	if !decodeJSONLimit(w, r, maxProfileBody, &request) {
		return
	}
	update := store.ProfileUpdate{}
	if request.DisplayName != nil {
		name := strings.TrimSpace(*request.DisplayName)
		if name == "" || len(name) > maxDisplayName {
			writeError(w, http.StatusBadRequest, "display name must be between 1 and 200 characters")
			return
		}
		update.DisplayName = &name
	}
	switch {
	case request.RemoveAvatar && request.Avatar != "":
		writeError(w, http.StatusBadRequest, "send either a new picture or remove_avatar, not both")
		return
	case request.RemoveAvatar:
		update.RemoveAvatar = true
	case strings.TrimSpace(request.Avatar) != "":
		data, contentType, err := avatar.Parse(request.Avatar)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		key, err := avatar.NewKey()
		if err != nil {
			s.internalError(w, "generate picture key", err)
			return
		}
		update.AvatarKey, update.AvatarData, update.ContentType = key, data, contentType
	case update.DisplayName == nil:
		writeError(w, http.StatusBadRequest, "a display name or a picture is required")
		return
	}
	if err := s.store.UpdateProfile(r.Context(), claimsFrom(r).UserID, update); err != nil {
		s.handleStoreError(w, "update profile", err)
		return
	}
	profile, err := s.store.Profile(r.Context(), claimsFrom(r).UserID)
	if err != nil {
		s.handleStoreError(w, "reload profile", err)
		return
	}
	writeJSON(w, http.StatusOK, s.profileResponse(profile))
}

// avatar serves a stored profile picture by its unguessable key.
//
// The route is deliberately public. A profile picture is rendered by other
// applications such as go-tell through a plain image tag, which cannot carry
// the authentication cookie, and the key is 256 bits of randomness rather than
// a user identifier. Nothing else about the user is exposed here.
func (s *Server) avatar(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !avatar.ValidKey(key) {
		writeError(w, http.StatusNotFound, "picture not found")
		return
	}
	picture, err := s.store.Picture(r.Context(), key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "picture not found")
			return
		}
		s.internalError(w, "load profile picture", err)
		return
	}
	w.Header().Set("Content-Type", picture.ContentType)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("ETag", avatar.ETag(picture.Data))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	http.ServeContent(w, r, "", picture.UpdatedAt, bytes.NewReader(picture.Data))
}

func (s *Server) profileResponse(profile store.Profile) profileResponse {
	return profileResponse{
		ID: profile.ID, Email: profile.Email, DisplayName: profile.DisplayName,
		AvatarURL: s.avatarURL(profile.AvatarKey), Memberships: profile.Memberships,
		IsSystemAdministrator: profile.IsSystemAdministrator, NameCustomized: profile.NameCustomized,
		CreatedAt: profile.CreatedAt, LastLoginAt: profile.LastLoginAt,
		ProfileUpdatedAt: profile.ProfileUpdatedAt, AvatarUpdatedAt: profile.AvatarUpdatedAt,
	}
}

func (s *Server) avatarURL(key *string) string {
	if key == nil || *key == "" {
		return ""
	}
	return s.cfg.BaseURL + "/api/v1/avatars/" + *key
}
