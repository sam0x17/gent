use super::*;
use tokio::sync::{Semaphore, oneshot};

#[tokio::test]
async fn cancelled_waiter_keeps_capacity_until_it_exits_and_never_executes() {
    let store = Arc::new(Mutex::new(0));
    let locked = store.clone();
    let (entered, ready) = oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let holder = tokio::task::spawn_blocking(move || {
        let _guard = locked.lock().unwrap();
        entered.send(()).unwrap();
        released.recv().unwrap();
    });
    ready.await.unwrap();
    let slots = Arc::new(Semaphore::new(1));
    let permit = slots.clone().acquire_owned().await.unwrap();
    let shared = store.clone();
    let task = tokio::spawn(run(shared, "test", move |value| {
        let _permit = permit;
        *value += 1;
        Ok(())
    }));
    tokio::time::sleep(Duration::from_millis(20)).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(slots.available_permits(), 0);
    release.send(()).unwrap();
    holder.await.unwrap();
    let _released = tokio::time::timeout(Duration::from_secs(2), slots.acquire())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*store.lock().unwrap(), 0);
    run(store.clone(), "test retry", |value| {
        *value += 1;
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(*store.lock().unwrap(), 1);
}

#[tokio::test]
async fn cancelling_an_active_transaction_keeps_capacity_until_commit() {
    let store = Arc::new(Mutex::new(0));
    let slots = Arc::new(Semaphore::new(1));
    let permit = slots.clone().acquire_owned().await.unwrap();
    let (entered, ready) = oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let task = tokio::spawn(run(store.clone(), "test", move |value| {
        let _permit = permit;
        entered.send(()).unwrap();
        released.recv().unwrap();
        *value += 1;
        Ok(())
    }));
    ready.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(slots.available_permits(), 0);
    release.send(()).unwrap();
    let _released = tokio::time::timeout(Duration::from_secs(2), slots.acquire())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*store.lock().unwrap(), 1);
}
