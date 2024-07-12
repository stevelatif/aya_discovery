use std::fmt::Error;
use chrono::prelude::*;
use std::sync::{Arc, Mutex};

use crate::models::fw::Fw;

pub struct Database {
    pub fws: Arc<Mutex<Vec<Fw>>>,
}

impl Database {
    pub fn new() -> Self {
        let fws = Arc::new(Mutex::new(vec![]));
        Database { fws }
    }

    pub fn create_fw(&self, fw: Fw) -> Result<Fw, Error> {
        let mut fws = self.fws.lock().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let created_at = Utc::now();
        let updated_at = Utc::now();
        let fw = Fw {
            id: Some(id),
            created_at: Some(created_at),
            updated_at: Some(updated_at),
            ..fw
        };
        fws.push(fw.clone());
        Ok(fw)
    }

    pub fn get_fws(&self) -> Vec<Fw> {
        let fws = self.fws.lock().unwrap();
        fws.clone()
    }

     pub fn get_fw_by_id(&self, id: &str) -> Option<Fw> {
        let fws = self.fws.lock().unwrap();
        fws.iter().find(|fw| fw.id == Some(id.to_string())).cloned()
    }

    pub fn update_fw_by_id(&self, id: &str, fw: Fw) -> Option<Fw> {
        let mut fws = self.fws.lock().unwrap();
        let updated_at = Utc::now();
        let fw = Fw {
            id: Some(id.to_string()),
            updated_at: Some(updated_at),
            ..fw
        };
        let index = fws.iter().position(|fw| fw.id == Some(id.to_string()))?;
        fws[index] = fw.clone();
        Some(fw)
    }

    pub fn delete_fw_by_id(&self, id: &str) -> Option<Fw> {
        let mut fws = self.fws.lock().unwrap();
        let index = fws.iter().position(|fw| fw.id == Some(id.to_string()))?;
        Some(fws.remove(index))
    }
}
