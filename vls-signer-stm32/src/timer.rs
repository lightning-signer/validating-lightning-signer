use alloc::boxed::Box;
use alloc::vec::Vec;
use cortex_m::interrupt::{free, CriticalSection};
use stm32f4xx_hal::{
    interrupt,
    pac::{Interrupt, NVIC, TIM2},
    timer::{CounterUs, Event},
};

static mut TIMER_TIM2: Option<CounterUs<TIM2>> = None;

pub trait TimerListener {
    fn on_tick(&self, cs: &CriticalSection);
}

static mut TIMER_LISTENERS: Vec<Box<dyn TimerListener>> = Vec::new();

pub fn start_tim2_interrupt(timer: CounterUs<TIM2>) {
    unsafe {
        TIMER_TIM2 = Some(timer);
        // enable interrupts
        NVIC::unpend(Interrupt::TIM2);
        NVIC::unmask(Interrupt::TIM2);
    }
}

pub fn add_listener(listener: Box<dyn TimerListener>) {
    unsafe {
        // ensure not started
        assert!(TIMER_TIM2.is_none());
        TIMER_LISTENERS.push(listener);
    }
}

#[interrupt]
fn TIM2() {
    unsafe {
        TIMER_TIM2.as_mut().unwrap().clear_interrupt(Event::Update);
        free(|cs| {
            for listener in &TIMER_LISTENERS {
                listener.on_tick(cs);
            }
        });
    }
}
