package portscan

import (
	"context"
	"sync"
)

// отделяет исходный ввод от адреса подключения
type target struct {
	host    string
	address string
}

// запускает пул со снапшотами данных
func (s *Scanner) scan(ctx context.Context, normalized []target, values []uint16) <-chan Result {
	type job struct {
		target target
		port   uint16
	}
	n := s.config.Concurrency
	jobs := make(chan job, n)
	results := make(chan Result, n)
	var workers sync.WaitGroup
	workers.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case j, ok := <-jobs:
					if !ok || ctx.Err() != nil {
						return
					}
					result := s.checker.Check(ctx, j.target.address, j.port, s.config.ConnectTimeout)
					result.Host = j.target.host
					select {
					case <-ctx.Done():
						return
					case results <- result:
					}
				}
			}
		}()
	}
	// Единственный продюсер управляет заданиями;
	// закрывает результаты только после остановки отправки всех воркеров
	go func() {
		defer close(results)
		func() {
			defer close(jobs)
			for _, target := range normalized {
				for _, port := range values {
					if ctx.Err() != nil {
						return
					}
					select {
					case <-ctx.Done():
						return
					case jobs <- job{target, port}:
					}
				}
			}
		}()
		workers.Wait()
	}()
	return results
}
