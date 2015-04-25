
#include "h2op.h"

namespace H2 {

EventSignal::EventSignal(event_base *base, int signum, Handler* H)
    :base(base), H(H)
{
    sig = evsignal_new(base, signum, sighandle, this);
    if(!sig)
        throw std::bad_alloc();
    evsignal_add(sig, NULL);
}

EventSignal::~EventSignal()
{
    event_del(sig);
    event_free(sig);
}

void EventSignal::sighandle(int s, short evt, void *raw)
{
    EventSignal *self = (EventSignal*)raw;
    try{
        if(self->H)
            self->H->signal(s);
        else
            event_base_loopexit(self->base, NULL);
    }catch(std::exception& e){
        fprintf(stderr, "Unhandled exception in %s: %s\n", __FUNCTION__, e.what());
    }
}

} // namespace H2
