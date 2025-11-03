//go:build integration

package integration

import (
	"log"
	"os"
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

const (
	kafkaBroker = "localhost:9092"
	auditTopic  = "test-audit-topic"
)

func TestMain(m *testing.M) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	// Kafka and Zookeeper
	network, err := pool.Client.CreateNetwork(docker.CreateNetworkOptions{
		Name: "kafka-net",
	})
	if err != nil {
		log.Fatalf("Could not create network: %s", err)
	}

	zookeeper, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "wurstmeister/zookeeper",
		Tag:        "latest",
		NetworkID:  network.ID,
	})
	if err != nil {
		log.Fatalf("Could not start zookeeper: %s", err)
	}

	kafka, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "wurstmeister/kafka",
		Tag:        "latest",
		NetworkID:  network.ID,
		PortBindings: map[docker.Port][]docker.PortBinding{
			"9092/tcp": {{HostPort: "9092"}},
		},
		Env: []string{
			"KAFKA_ADVERTISED_HOST_NAME=localhost",
			"KAFKA_ZOOKEEPER_CONNECT=zookeeper:2181",
			"KAFKA_CREATE_TOPICS=Topic:" + auditTopic + ":1:1",
		},
	})
	if err != nil {
		log.Fatalf("Could not start kafka: %s", err)
	}

	// Vault
	vault, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "vault",
		Tag:        "latest",
		PortBindings: map[docker.Port][]docker.PortBinding{
			"8200/tcp": {{HostPort: "8200"}},
		},
		Env: []string{
			"VAULT_DEV_ROOT_TOKEN_ID=myroot",
			"VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		},
	})
	if err != nil {
		log.Fatalf("Could not start vault: %s", err)
	}

	// Wait for services to be ready
	if err := pool.Retry(func() error {
		_, err := kafka.Exec([]string{"kafka-topics", "--zookeeper", "zookeeper:2181", "--list"}, dockertest.ExecOptions{})
		return err
	}); err != nil {
		log.Fatalf("Could not connect to kafka: %s", err)
	}

	if err := pool.Retry(func() error {
		_, err := vault.Exec([]string{"vault", "status"}, dockertest.ExecOptions{})
		return err
	}); err != nil {
		log.Fatalf("Could not connect to vault: %s", err)
	}

	code := m.Run()

	// You can't defer this because os.Exit doesn't care for defer
	if err := pool.Purge(zookeeper); err != nil {
		log.Fatalf("Could not purge zookeeper: %s", err)
	}
	if err := pool.Purge(kafka); err != nil {
		log.Fatalf("Could not purge kafka: %s", err)
	}
	if err := pool.Purge(vault); err != nil {
		log.Fatalf("Could not purge vault: %s", err)
	}
	if err := pool.Client.RemoveNetwork(network.ID); err != nil {
		log.Fatalf("Could not remove network: %s", err)
	}

	os.Exit(code)
}
