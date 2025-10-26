// internal/infrastructure/persistence/postgres/keys.go
package postgres

import (
   "context"
   "errors"

   "github.com/jackc/pgx/v5/pgxpool"
   "github.com/turtacn/cbc/internal/domain/models"
)

type KeyRepo struct{ db *pgxpool.Pool }

func NewKeyRepo(db *pgxpool.Pool) *KeyRepo { return &KeyRepo{db: db} }

func (r *KeyRepo) ActiveKey() (*models.KeyMeta, []byte, error) {
   const q = `select kid, alg, public_pem, private_or_shared from keys where active=true limit 1`
   var meta models.KeyMeta
   var priv []byte
   err := r.db.QueryRow(context.Background(), q).Scan(&meta.KID, &meta.Alg, &meta.PublicPEM, &priv)
   if err != nil { return nil, nil, err }
   meta.Active = true
   return &meta, priv, nil
}

func (r *KeyRepo) FindByKID(kid string) (*models.KeyMeta, []byte, error) {
   const q = `select kid, alg, public_pem, private_or_shared, active from keys where kid=$1`
   var meta models.KeyMeta
   var priv []byte
   if err := r.db.QueryRow(context.Background(), q, kid).Scan(&meta.KID, &meta.Alg, &meta.PublicPEM, &priv, &meta.Active); err != nil {
      return nil, nil, errors.New("not found")
   }
   return &meta, priv, nil
}
